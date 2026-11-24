package com.example.jammoney.auth.service;

import com.example.jammoney.auth.jwt.JwtTokenProvider;
import com.example.jammoney.auth.repository.RefreshTokenRepository;
import com.example.jammoney.exception.InvalidRefreshTokenException;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final StringRedisTemplate redisTemplate;

    /** 로그인 시 refresh 저장 (해시 저장) — 토큰 exp 기준 TTL 반영 */
    public void saveRefreshToken(Long userId, String refreshToken) {
        Claims c = jwtTokenProvider.parseClaims(refreshToken);
        if (c == null || !jwtTokenProvider.isRefreshToken(c)) {
            throw new InvalidRefreshTokenException();
        }
        Duration ttl = calculateRemainingTime(c);
        refreshTokenRepository.saveByUserId(userId, refreshToken, ttl);
    }

    /** 제공된 refresh 토큰이 유효하고 내 저장소와 일치하는지 검증 (해시 비교) */
    public void assertTokenValid(Long userId, String providedToken) {
        if (providedToken == null || providedToken.isBlank()) throw new InvalidRefreshTokenException();

        Claims c = jwtTokenProvider.parseClaims(providedToken);
        if (c == null || !jwtTokenProvider.isRefreshToken(c)) throw new InvalidRefreshTokenException();

        Long uidFromToken = jwtTokenProvider.getUserId(c);
        if (uidFromToken == null || !uidFromToken.equals(userId)) throw new InvalidRefreshTokenException();

        String hash = sha256(providedToken);
        if (!refreshTokenRepository.existsByUserIdAndHash(userId, hash)) {
            throw new InvalidRefreshTokenException();
        }
    }

    /** refresh 토큰 회전 — family 유지, 해시 저장 (exp/TTL 동기화) */
    public String reissueRefreshToken(Long userId, String oldToken, long ver) {
        // 1) 유효성/정합성 확인
        assertTokenValid(userId, oldToken);

        // 기존 권한을 현재 버전으로 승격하지 않는다. 로그아웃과의 경합은 저장소에서도 재검사한다.
        Claims oldC = jwtTokenProvider.parseClaims(oldToken);
        if (oldC == null || jwtTokenProvider.getTokenVersion(oldC) != ver) {
            throw new InvalidRefreshTokenException();
        }
        String username = jwtTokenProvider.getUsername(oldC);
        String familyId = jwtTokenProvider.getFamilyId(oldC);
        String newToken = jwtTokenProvider.generateRefreshToken(userId, username, familyId, ver);

        Claims newClaims = jwtTokenProvider.parseClaims(newToken);
        if (newClaims == null || !refreshTokenRepository.rotate(
                userId, oldToken, newToken, calculateRemainingTime(newClaims), ver)) {
            throw new InvalidRefreshTokenException();
        }

        return newToken;
    }

    /** 단일 기기 로그아웃: 이미 회전된 구 RT도 같은 family의 후속 RT를 폐기할 수 있다. */
    public void invalidateOne(Long userId, String providedToken) {
        if (userId == null || providedToken == null || providedToken.isBlank()) return;
        Claims claims = jwtTokenProvider.parseClaims(providedToken);
        if (claims == null || !jwtTokenProvider.isRefreshToken(claims)
                || !userId.equals(jwtTokenProvider.getUserId(claims))) return;
        String familyId = jwtTokenProvider.getFamilyId(claims);
        if (familyId == null || familyId.isBlank()) {
            // Compatibility for legacy tokens without a family claim.
            refreshTokenRepository.deleteByUserIdAndHash(userId, sha256(providedToken));
            return;
        }
        refreshTokenRepository.revokeFamily(userId, familyId, calculateRemainingTime(claims));
    }

    /** 전체 로그아웃: ver++ 후 refresh 모두 삭제 (멱등) */
    public void invalidateAll(Long userId) {
        bumpRevocationVersion(userId);
        refreshTokenRepository.deleteAllByUserId(userId);
    }

    /** Access Token 블랙리스트 등록 (남은 TTL = exp-now) */
    public void blacklistAccessToken(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) return;

        Claims c = jwtTokenProvider.parseClaims(accessToken);
        if (c == null) return; // 무효/만료 등
        long remainSec = jwtTokenProvider.getRemainingSeconds(c);
        if (remainSec <= 0) return;

        String key = "blacklist:access:" + sha256(accessToken);
        redisTemplate.opsForValue().set(key, "1", remainSec, TimeUnit.SECONDS);
    }

    /** Access Token 블랙리스트 확인 */
    public boolean isAccessTokenBlacklisted(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) return false;
        String key = "blacklist:access:" + sha256(accessToken);
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    // ── ver(전역 무효화 버전)
    private String revocationVerKey(Long userId) { return "user:revocation_ver:" + userId; }

    /** 현재 전역 무효화 버전 (없으면 0) */
    public long getRevocationVersion(Long userId) {
        if (userId == null) return 0L;
        String v = redisTemplate.opsForValue().get(revocationVerKey(userId));
        try { return (v == null ? 0L : Long.parseLong(v)); }
        catch (NumberFormatException e) { return 0L; }
    }

    /** 전역 무효화: 버전 + 1 반환 */
    public long bumpRevocationVersion(Long userId) {
        if (userId == null) return 0L;
        Long newVer = redisTemplate.opsForValue().increment(revocationVerKey(userId));
        return (newVer == null ? 0L : newVer);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private Duration calculateRemainingTime(Claims c) {
        long remainSec = Math.max(1, jwtTokenProvider.getRemainingSeconds(c)); // 최소 1초
        return Duration.ofSeconds(remainSec);
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
}
