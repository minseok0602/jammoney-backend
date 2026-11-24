package com.example.jammoney.auth.repository;

import com.example.jammoney.auth.jwt.JwtTokenProvider;
import com.example.jammoney.exception.InvalidRefreshTokenException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Repository;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Objects;
import java.util.Set;
import java.util.List;

@Slf4j
@Repository
@RequiredArgsConstructor
public class RefreshTokenRepositoryImpl implements RefreshTokenRepository {

    private static final RedisScript<Long> ROTATE_SCRIPT = RedisScript.of(
            new ClassPathResource("redis/rotate-refresh-token.lua"), Long.class);
    private static final RedisScript<Long> SAVE_SCRIPT = RedisScript.of(
            new ClassPathResource("redis/save-refresh-token.lua"), Long.class);
    private static final RedisScript<Long> REVOKE_FAMILY_SCRIPT = RedisScript.of(
            new ClassPathResource("redis/revoke-refresh-family.lua"), Long.class);

    private final StringRedisTemplate redisTemplate;
    private final JwtTokenProvider jwtTokenProvider;
    private final ObjectMapper objectMapper;

    // 특정 유저의 토큰 메타 데이터를 저장할 key 이름 - RefreshMeta를 value로서 저장
    private String tokenKey(Long userId, String jti) { return "refresh:uid:" + userId + ":token:" + jti; }
    // 특정 유저의 특정 토큰 해시를 저장할 key 이름 - jti를 value로서 저장
    private String hashKey(Long userId, String hash) { return "refresh:uid:" + userId + ":hash:" + hash; }
    // 특정 유저가 가진 모든 토큰들을 저장할 key 이름 - 특정 user의 모든 토큰 해시들을 저장
    private String hashSet(Long userId)             { return "refresh:uid:" + userId + ":hashes"; }

    private String familyRevokedKey(Long userId, String familyId) {
        return "refresh:uid:" + userId + ":family:" + sha256(familyId == null ? "" : familyId) + ":revoked";
    }

    // ── Meta DTO ───────────────────────────────────────────────────────────────
    @Data @NoArgsConstructor @AllArgsConstructor
    static class RefreshMeta {
        private Long userId;
        private Long expEpochSec; // 정보용(만료 판단은 TTL로 충분)
        private String status;    // "active" / "revoked"
        private String ua;        // optional
        private String ip;        // optional
        private String familyId;  // optional
    }


    private static String sha256(String in) {
        try {
            var md = MessageDigest.getInstance("SHA-256");
            byte[] dig = md.digest(in.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(dig.length * 2);
            for (byte b : dig) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** TTL(sec)을 만료 시각과 정합성 있게 보정 (만료 초과 금지) */
    private long alignedTtlSec(Duration requestedTtl, long expMs) {
        if (expMs <= 0) return 0L;
        long nowMs = System.currentTimeMillis();
        long remainMs = Math.max(0, expMs - nowMs);
        long remainSec = remainMs / 1000;
        long req = (requestedTtl == null) ? remainSec : Math.max(0, requestedTtl.getSeconds());
        return Math.min(req, remainSec);
    }

    @Override
    public void saveByUserId(Long userId, String refreshTokenRaw, Duration ttl) {
        Claims c = jwtTokenProvider.parseClaims(refreshTokenRaw);
        if (c == null || !jwtTokenProvider.isRefreshToken(c)) {
            throw new IllegalArgumentException("유효하지 않은 refresh token입니다.");
        }

        if (!Objects.equals(userId, jwtTokenProvider.getUserId(c))) {
            throw new IllegalArgumentException("refresh token의 소유자가 일치하지 않습니다.");
        }

        String jti  = jwtTokenProvider.getJti(c);

        // 만료 시간 계산
        long expMs  = jwtTokenProvider.getExpirationMillis(c);
        String hash = sha256(refreshTokenRaw);

        if (userId == null || jti == null || jti.isBlank() || expMs <= 0) {
            throw new IllegalArgumentException("refresh token 저장 인자가 올바르지 않습니다.");
        }

        long ttlSec = alignedTtlSec(ttl, expMs);
        if (ttlSec <= 0) {
            throw new IllegalArgumentException("refresh token이 만료됐습니다.");
        }

        RefreshMeta meta = new RefreshMeta(userId, expMs / 1000, "active", null, null, c.get("fam", String.class));
        final String json;
        try {
            json = objectMapper.writeValueAsString(meta);
        } catch (Exception e) {
            throw new IllegalStateException("refresh_token 직렬화 실패", e);
        }

        // value를 저장할 key값들을 찾음
        final String keyToken  = tokenKey(userId, jti);
        final String keyHash   = hashKey(userId, hash);
        final String keyHashes = hashSet(userId);

        Long result = redisTemplate.execute(SAVE_SCRIPT,
                List.of(keyToken, keyHash, keyHashes, familyRevokedKey(userId, jwtTokenProvider.getFamilyId(c)),
                        "user:revocation_ver:" + userId),
                json, jti, hash, Long.toString(ttlSec), Long.toString(jwtTokenProvider.getTokenVersion(c)));
        if (result == null) throw new IllegalStateException("refresh token 저장 결과를 확인할 수 없습니다.");
        if (result != 1L) throw new InvalidRefreshTokenException();
        log.info("refresh_token 저장 성공 uid={} jti={}", userId, jti);
    }

    @Override
    public boolean rotate(Long userId, String oldToken, String newToken, Duration ttl, long expectedVersion) {
        Claims oldClaims = jwtTokenProvider.parseClaims(oldToken);
        Claims newClaims = jwtTokenProvider.parseClaims(newToken);
        if (userId == null || expectedVersion < 0 || oldClaims == null || newClaims == null
                || !jwtTokenProvider.isRefreshToken(oldClaims) || !jwtTokenProvider.isRefreshToken(newClaims)
                || !Objects.equals(userId, jwtTokenProvider.getUserId(oldClaims))
                || !Objects.equals(userId, jwtTokenProvider.getUserId(newClaims))
                || jwtTokenProvider.getTokenVersion(oldClaims) != expectedVersion
                || jwtTokenProvider.getTokenVersion(newClaims) != expectedVersion
                || !Objects.equals(jwtTokenProvider.getFamilyId(oldClaims), jwtTokenProvider.getFamilyId(newClaims))) {
            return false;
        }

        String oldJti = jwtTokenProvider.getJti(oldClaims);
        String newJti = jwtTokenProvider.getJti(newClaims);
        if (oldJti == null || oldJti.isBlank() || newJti == null || newJti.isBlank() || oldJti.equals(newJti)) {
            return false;
        }
        long expMs = jwtTokenProvider.getExpirationMillis(newClaims);
        long ttlSec = alignedTtlSec(ttl, expMs);
        if (ttlSec <= 0) throw new IllegalArgumentException("새 refresh token이 만료됐습니다.");

        String oldHash = sha256(oldToken);
        String newHash = sha256(newToken);
        String familyId = jwtTokenProvider.getFamilyId(oldClaims);
        RefreshMeta meta = new RefreshMeta(userId, expMs / 1000, "active", null, null, familyId);
        final String json;
        try {
            json = objectMapper.writeValueAsString(meta);
        } catch (Exception e) {
            throw new IllegalStateException("refresh token 직렬화 실패", e);
        }

        Long result = redisTemplate.execute(ROTATE_SCRIPT,
                List.of(hashKey(userId, oldHash), tokenKey(userId, oldJti),
                        hashKey(userId, newHash), tokenKey(userId, newJti), hashSet(userId),
                        "user:revocation_ver:" + userId, familyRevokedKey(userId, familyId)),
                oldJti, newJti, oldHash, newHash, json, Long.toString(ttlSec),
                Long.toString(expectedVersion), userId.toString(), familyId == null ? "" : familyId);
        if (result == null) throw new IllegalStateException("refresh token 회전 결과를 확인할 수 없습니다.");
        return result == 1L;
    }

    @Override
    public void revokeFamily(Long userId, String familyId, Duration minimumTtl) {
        if (userId == null || familyId == null || familyId.isBlank()) {
            throw new IllegalArgumentException("폐기할 refresh token family가 필요합니다.");
        }
        long ttlMillis = Math.max(1L, minimumTtl.toMillis());
        Long result = redisTemplate.execute(REVOKE_FAMILY_SCRIPT,
                List.of(hashSet(userId), familyRevokedKey(userId, familyId)),
                "refresh:uid:" + userId + ":", familyId, Long.toString(ttlMillis), userId.toString());
        if (result == null) throw new IllegalStateException("refresh token family 폐기 결과를 확인할 수 없습니다.");
    }

    @Override
    public boolean existsByUserIdAndHash(Long userId, String refreshTokenHash) {
        try {
            if (userId == null || refreshTokenHash == null || refreshTokenHash.isBlank()) return false;

            String jti = redisTemplate.opsForValue().get(hashKey(userId, refreshTokenHash));
            if (jti == null || jti.isBlank()) return false;

            String json = redisTemplate.opsForValue().get(tokenKey(userId, jti));
            if (json == null) return false;

            RefreshMeta meta = objectMapper.readValue(json, RefreshMeta.class);
            if (!Objects.equals(meta.getUserId(), userId)) return false;
            if (!"active".equalsIgnoreCase(meta.getStatus())) return false;

            return true;
        } catch (Exception e) {
            log.warn("refresh_token 존재 확인 중 에러 발생: {}", e.getMessage());
            return false;
        }
    }

    @Override
    public void deleteByUserIdAndHash(Long userId, String refreshTokenHash) {
        if (userId == null || refreshTokenHash == null || refreshTokenHash.isBlank()) return;

        String jti = redisTemplate.opsForValue().get(hashKey(userId, refreshTokenHash));
        final String keyToken  = (jti == null ? null : tokenKey(userId, jti));
        final String keyHash   = hashKey(userId, refreshTokenHash);
        final String keyHashes = hashSet(userId);

        redisTemplate.execute(new SessionCallback<Void>() {
            @Override
            @SuppressWarnings("unchecked")
            public Void execute(RedisOperations operations) throws DataAccessException {
                RedisOperations<String, String> ops = (RedisOperations<String, String>) operations;
                ops.multi();
                if (keyToken != null) ops.delete(keyToken);             // 메타 삭제(존재 시)
                ops.delete(keyHash);                                     // 해시 매핑 삭제
                ops.opsForSet().remove(keyHashes, refreshTokenHash);     // keyHashes 목록에서 이 hashToken 제거
                ops.exec();
                return null;
            }
        });
        log.info("refresh_token 하나 삭제 완료 uid={} jti={}", userId, jti);
    }

    @Override
    public void deleteAllByUserId(Long userId) {
        if (userId == null) return;

        final String keyHashes = hashSet(userId);

        // 해당 user의 토큰 해시들을 모두 모음 == 삭제해야할 토큰 해시들 모음
        Set<String> hashes = redisTemplate.opsForSet().members(keyHashes);


        java.util.List<String> keysToDelete = new java.util.ArrayList<>();
        if (hashes != null && !hashes.isEmpty()) {
            for (String h : hashes) {
                // keyHash들의 jti 값을 가져옴
                String jti = redisTemplate.opsForValue().get(hashKey(userId, h));
                if (jti != null && !jti.isBlank()) {
                    // tokenKey의 메타 데이터 삭제를 위해 리스트업
                    keysToDelete.add(tokenKey(userId, jti));
                }
                // hashKey의 jti 삭제를 위해 리스트업
                keysToDelete.add(hashKey(userId, h)); // 해시 매핑 키
            }
        }
        // keyHashes 삭제를 위해 리스트업
        keysToDelete.add(keyHashes);

        // keysToDelete에는 삭제해야할 모든 key값들이 저장돼있음
        redisTemplate.execute(new SessionCallback<Void>() {
            @Override
            @SuppressWarnings("unchecked")
            public Void execute(RedisOperations operations) throws DataAccessException {
                RedisOperations<String, String> ops = (RedisOperations<String, String>) operations;
                ops.multi();
                for (String k : keysToDelete) {
                    // 삭제해야할 모든 키들 다 삭제
                    ops.delete(k);
                }
                ops.exec();
                return null;
            }
        });
        log.info("uid={} 에 대한 모든 refresh_token /매핑/세트 키 삭제 완료. 삭제건수={}", userId, keysToDelete.size());
    }
}
