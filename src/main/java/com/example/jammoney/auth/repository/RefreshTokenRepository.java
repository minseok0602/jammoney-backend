package com.example.jammoney.auth.repository;

import org.springframework.stereotype.Repository;

import java.time.Duration;

@Repository
public interface RefreshTokenRepository {

    void saveByUserId(Long userId, String refreshTokenRaw, Duration ttl);

    boolean existsByUserIdAndHash(Long userId, String hash);

    /** Consume the old RT and persist its successor in one conditional operation. */
    boolean rotate(Long userId, String oldToken, String newToken, Duration ttl, long expectedVersion);

    /** Revoke every active descendant in this login family, including rotations racing with logout. */
    void revokeFamily(Long userId, String familyId, Duration minimumTtl);

    void deleteByUserIdAndHash(Long userId, String hash);

    void deleteAllByUserId(Long userId);
}
