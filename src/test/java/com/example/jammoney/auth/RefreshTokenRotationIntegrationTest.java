package com.example.jammoney.auth;

import com.example.jammoney.auth.jwt.JwtTokenProvider;
import com.example.jammoney.auth.repository.RefreshTokenRepositoryImpl;
import com.example.jammoney.auth.service.CustomUserDetailsService;
import com.example.jammoney.auth.service.RefreshTokenService;
import com.example.jammoney.exception.InvalidRefreshTokenException;
import com.example.jammoney.user.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.lettuce.core.resource.DefaultClientResources;
import org.junit.jupiter.api.*;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.test.util.ReflectionTestUtils;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/** Real Redis, production JWT/repository/service; no SQL or external service calls. */
@Timeout(30)
class RefreshTokenRotationIntegrationTest {
    private static final AtomicLong IDS = new AtomicLong(8_460_000);
    private static GenericContainer<?> container;
    private static DefaultClientResources resources;
    private static LettuceConnectionFactory factory;
    private static StringRedisTemplate redis;
    private static JwtTokenProvider jwt;
    private static RefreshTokenRepositoryImpl repository;
    private static RefreshTokenService service;
    private long uid;
    private String old;

    @BeforeAll static void connect() {
        String host = System.getenv("RT_TEST_REDIS_HOST");
        int port = Integer.parseInt(System.getenv().getOrDefault("RT_TEST_REDIS_PORT", "6379"));
        if (host == null || host.isBlank()) {
            container = new GenericContainer<>(DockerImageName.parse(
                    "redis@sha256:7f7d30b7fdd09467bac58198a1f166dd69789d348d4fe859cccb20e0cf287fbe"))
                    .withExposedPorts(6379);
            container.start();
            host = container.getHost();
            port = container.getMappedPort(6379);
        }
        resources = DefaultClientResources.builder().ioThreadPoolSize(2).computationThreadPoolSize(2).build();
        factory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(host, port),
                LettuceClientConfiguration.builder().clientResources(resources)
                        .commandTimeout(Duration.ofSeconds(2)).build());
        factory.afterPropertiesSet();
        factory.start();
        redis = new StringRedisTemplate(factory);
        redis.setEnableTransactionSupport(true); // same setting as production RedisConfig
        jwt = new JwtTokenProvider(new CustomUserDetailsService(mock(UserRepository.class)));
        ReflectionTestUtils.setField(jwt, "secretKey",
                "rotation-test-only-fake-secret-0123456789abcdef-0123456789abcdef-0123456789abcdef");
        ReflectionTestUtils.setField(jwt, "refreshValiditySec", 3600L);
        ReflectionTestUtils.setField(jwt, "accessValiditySec", 600L);
        repository = new RefreshTokenRepositoryImpl(redis, jwt, new ObjectMapper());
        service = new RefreshTokenService(repository, jwt, redis);
    }

    @BeforeEach void seed() {
        uid = IDS.incrementAndGet();
        assertTrue(redis.keys(prefix() + "*").isEmpty(), "fixture user must be unused");
        assertNotEquals(Boolean.TRUE, redis.hasKey(versionKey()));
        old = token(0);
        service.saveRefreshToken(uid, old);
        assertTrue(valid(old));
    }

    @AfterEach void cleanup() {
        Set<String> keys = redis.keys(prefix() + "*");
        if (keys != null && !keys.isEmpty()) redis.delete(keys);
        redis.delete(versionKey());
    }

    @AfterAll static void disconnect() throws Exception {
        try {
            if (factory != null) factory.destroy();
            if (resources != null) resources.shutdown().get(5, TimeUnit.SECONDS);
        } finally {
            if (container != null) container.stop();
        }
    }

    @Test void successorIsStoredWithBoundedTtlAndOldTokenCannotBeReused() {
        String next = service.reissueRefreshToken(uid, old, 0);
        assertFalse(valid(old));
        assertTrue(valid(next));
        assertThrows(InvalidRefreshTokenException.class, () -> service.reissueRefreshToken(uid, old, 0));
        assertEquals(Set.of(hash(next)), redis.opsForSet().members(indexKey()));
        Long ttl = redis.getExpire(prefix() + "hash:" + hash(next));
        assertNotNull(ttl);
        assertTrue(ttl > 0 && ttl <= jwt.getRemainingSeconds(jwt.parseClaims(next)) + 1);
        String child = service.reissueRefreshToken(uid, next, 0);
        assertFalse(valid(next));
        assertTrue(valid(child));
    }

    @RepeatedTest(10) void simultaneousValidatedReadsHaveOnlyOneWinner() throws Exception {
        var gate = new CyclicBarrier(2);
        var gated = spy(repository);
        doAnswer(invocation -> {
            boolean exists = (boolean) invocation.callRealMethod();
            if (exists) gate.await(5, TimeUnit.SECONDS);
            return exists;
        }).when(gated).existsByUserIdAndHash(eq(uid), eq(hash(old)));
        assertSingleWinner(new RefreshTokenService(gated, jwt, redis), 2);
    }

    @RepeatedTest(10) void simultaneousRequestsHaveOnlyOneWinnerWithoutReadGate() throws Exception {
        assertSingleWinner(service, 2);
    }

    @RepeatedTest(3) void twentyConcurrentRequestsStillHaveOnlyOneWinner() throws Exception {
        assertSingleWinner(service, 20);
    }

    @Test void logoutAfterValidationPreventsSuccessorStorage() throws Exception {
        var validated = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var gated = spy(repository);
        doAnswer(invocation -> {
            boolean exists = (boolean) invocation.callRealMethod();
            validated.countDown();
            if (!release.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("gate timeout");
            return exists;
        }).when(gated).existsByUserIdAndHash(eq(uid), eq(hash(old)));
        var target = new RefreshTokenService(gated, jwt, redis);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<Boolean> result = pool.submit(() -> {
                try { target.reissueRefreshToken(uid, old, 0); return true; }
                catch (InvalidRefreshTokenException expected) { return false; }
            });
            assertTrue(validated.await(5, TimeUnit.SECONDS));
            service.invalidateAll(uid);
            release.countDown();
            assertFalse(result.get(10, TimeUnit.SECONDS));
            assertTrue(redis.keys(prefix() + "*").isEmpty());
            assertEquals(1L, service.getRevocationVersion(uid));
        } finally {
            release.countDown();
            pool.shutdownNow();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test void oldTokenCannotBeUpgradedToNewLogoutVersion() {
        service.bumpRevocationVersion(uid);
        assertThrows(InvalidRefreshTokenException.class, () -> service.reissueRefreshToken(uid, old, 1));
        assertThrows(InvalidRefreshTokenException.class, () -> service.reissueRefreshToken(uid, old, 0));
        assertEquals(Set.of(hash(old)), redis.opsForSet().members(indexKey()));
    }

    @Test void indexTypeFailureDoesNotConsumeOldTokenOrCreatePartialSuccessor() {
        redis.opsForValue().set(indexKey(), "invalid-index-type");
        Set<String> before = redis.keys(prefix() + "*");
        assertThrows(DataAccessException.class, () -> service.reissueRefreshToken(uid, old, 0));
        assertTrue(valid(old));
        assertEquals(before, redis.keys(prefix() + "*"));
    }

    @Test void storageFailureIsPropagatedInsteadOfReportedAsSuccess() {
        redis.opsForValue().set(indexKey(), "invalid-index-type");
        String another = token(0);
        assertThrows(RuntimeException.class, () -> service.saveRefreshToken(uid, another));
    }

    @Test void differentOwnerCannotRotateStoredToken() {
        assertThrows(InvalidRefreshTokenException.class, () -> service.reissueRefreshToken(uid + 1, old, 0));
        assertTrue(valid(old));
    }

    @Test void expiredSuccessorIsRejectedBeforeOldTokenIsConsumed() {
        String expired;
        ReflectionTestUtils.setField(jwt, "refreshValiditySec", 0L);
        try { expired = token(0); }
        finally { ReflectionTestUtils.setField(jwt, "refreshValiditySec", 3600L); }
        assertThrows(IllegalArgumentException.class,
                () -> repository.rotate(uid, old, expired, Duration.ofHours(1), 0));
        assertTrue(valid(old));
        assertEquals(Set.of(hash(old)), redis.opsForSet().members(indexKey()));
    }

    @Test void oldRotatedTokenRevokesEveryDescendantOnlyInItsOwnFamily() {
        String otherDevice = jwt.generateRefreshToken(uid, "test@example.invalid", "other-family-" + uid, 0);
        service.saveRefreshToken(uid, otherDevice);
        String latest = service.reissueRefreshToken(uid, old, 0);
        latest = service.reissueRefreshToken(uid, latest, 0);
        service.invalidateOne(uid, old);
        String revoked = latest;
        assertFalse(valid(revoked));
        assertThrows(InvalidRefreshTokenException.class, () -> service.reissueRefreshToken(uid, revoked, 0));
        assertTrue(valid(otherDevice));
        assertEquals(Set.of(hash(otherDevice)), redis.opsForSet().members(indexKey()));
        assertTrue(valid(service.reissueRefreshToken(uid, otherDevice, 0)));
        service.invalidateOne(uid, old); // idempotent even though the submitted RT was already consumed
    }

    @Test void revokedFamilyCannotBeRestoredBySavingAnOldToken() {
        service.invalidateOne(uid, old);
        assertThrows(InvalidRefreshTokenException.class, () -> service.saveRefreshToken(uid, old));
        assertFalse(valid(old));
        String newLogin = jwt.generateRefreshToken(uid, "test@example.invalid", "new-login-" + uid, 0);
        service.saveRefreshToken(uid, newLogin);
        assertTrue(valid(newLogin));
    }

    @Test void revocationTtlCoversTheLongestLivedDescendant() {
        String shortLived;
        ReflectionTestUtils.setField(jwt, "refreshValiditySec", 120L);
        try { shortLived = token(0); }
        finally { ReflectionTestUtils.setField(jwt, "refreshValiditySec", 3600L); }
        // Same family, and more than one RT covers legacy forked sessions too.
        service.saveRefreshToken(uid, shortLived);
        String latest = service.reissueRefreshToken(uid, shortLived, 0);
        Long latestTtl = redis.getExpire(prefix() + "hash:" + hash(latest));
        service.invalidateOne(uid, shortLived);
        Set<String> markers = redis.keys(prefix() + "family:*");
        assertEquals(1, markers.size());
        assertTrue(redis.getExpire(markers.iterator().next()) >= latestTtl - 1);
        assertFalse(valid(old));
        assertFalse(valid(latest));
    }

    @RepeatedTest(10) void familyLogoutRacingWithRotationLeavesNoUsableDescendant() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(2);
        var start = new CountDownLatch(1);
        try {
            Future<String> rotation = pool.submit(() -> {
                start.await();
                try { return service.reissueRefreshToken(uid, old, 0); }
                catch (InvalidRefreshTokenException expected) { return null; }
            });
            Future<?> logout = pool.submit(() -> {
                start.await();
                service.invalidateOne(uid, old);
                return null;
            });
            start.countDown();
            String successor = rotation.get(10, TimeUnit.SECONDS);
            logout.get(10, TimeUnit.SECONDS);
            if (successor != null) assertFalse(valid(successor));
            assertFalse(valid(old));
            assertFalse(Boolean.TRUE.equals(redis.hasKey(indexKey())));
        } finally {
            start.countDown();
            pool.shutdownNow();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test void familyLogoutAfterValidationBlocksTheDelayedRotation() throws Exception {
        var validated = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var gated = spy(repository);
        doAnswer(invocation -> {
            boolean exists = (boolean) invocation.callRealMethod();
            validated.countDown();
            assertTrue(release.await(5, TimeUnit.SECONDS));
            return exists;
        }).when(gated).existsByUserIdAndHash(eq(uid), eq(hash(old)));
        var target = new RefreshTokenService(gated, jwt, redis);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<Boolean> result = pool.submit(() -> {
                try { target.reissueRefreshToken(uid, old, 0); return true; }
                catch (InvalidRefreshTokenException expected) { return false; }
            });
            assertTrue(validated.await(5, TimeUnit.SECONDS));
            service.invalidateOne(uid, old);
            release.countDown();
            assertFalse(result.get(10, TimeUnit.SECONDS));
            assertFalse(Boolean.TRUE.equals(redis.hasKey(indexKey())));
        } finally {
            release.countDown();
            pool.shutdownNow();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test void foreignOwnerAndAccessTokenCannotRevokeFamily() {
        service.invalidateOne(uid + 1, old);
        String access = jwt.generateAccessToken(uid, "test@example.invalid", List.of("ROLE_USER"), 0);
        service.invalidateOne(uid, access);
        assertTrue(valid(old));
    }

    private void assertSingleWinner(RefreshTokenService target, int workers) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(workers);
        var ready = new CountDownLatch(workers);
        var start = new CountDownLatch(1);
        try {
            List<Future<String>> futures = new ArrayList<>();
            for (int i = 0; i < workers; i++) {
                futures.add(pool.submit(() -> {
                    ready.countDown();
                    if (!start.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("start timeout");
                    try { return target.reissueRefreshToken(uid, old, 0); }
                    catch (InvalidRefreshTokenException expected) { return null; }
                }));
            }
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            List<String> winners = new ArrayList<>();
            for (var future : futures) {
                String result = future.get(10, TimeUnit.SECONDS);
                if (result != null) winners.add(result);
            }
            assertEquals(1, winners.size());
            String winner = winners.get(0);
            assertTrue(valid(winner));
            assertFalse(valid(old));
            assertEquals(Set.of(hash(winner)), redis.opsForSet().members(indexKey()));
            assertTrue(valid(service.reissueRefreshToken(uid, winner, 0)));
        } finally {
            start.countDown();
            pool.shutdownNow();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    private String token(long version) { return jwt.generateRefreshToken(uid, "test@example.invalid", "family-" + uid, version); }
    private boolean valid(String token) { return repository.existsByUserIdAndHash(uid, hash(token)); }
    private String prefix() { return "refresh:uid:" + uid + ":"; }
    private String indexKey() { return prefix() + "hashes"; }
    private String versionKey() { return "user:revocation_ver:" + uid; }
    private static String hash(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }
}
