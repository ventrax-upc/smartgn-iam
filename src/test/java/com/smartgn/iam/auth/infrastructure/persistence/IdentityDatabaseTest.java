package com.smartgn.iam.auth.infrastructure.persistence;

import static org.junit.jupiter.api.Assertions.*;

import com.smartgn.iam.IamServiceApplication;
import com.smartgn.iam.auth.application.port.in.IdentityOperations;
import com.smartgn.iam.auth.infrastructure.security.JwtProvider;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

@SpringBootTest(classes = IamServiceApplication.class)
@EnabledIfEnvironmentVariable(named = "SMARTGN_TEST_DATABASE_URL", matches = ".+")
class IdentityDatabaseTest {
    @Autowired IdentityOperations operations;
    @Autowired JdbcTemplate db;
    @Autowired JwtProvider jwt;
    @Autowired JdbcAccountRepository accounts;

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry p) {
        p.add("spring.datasource.url", () -> System.getenv("SMARTGN_TEST_DATABASE_URL"));
        p.add("spring.datasource.username", () -> System.getenv("SMARTGN_TEST_DATABASE_USERNAME"));
        p.add("spring.datasource.password", () -> System.getenv("SMARTGN_TEST_DATABASE_PASSWORD"));
        p.add("smartgn.security.jwt.secret", () -> "isolated-database-test-jwt-key-0123456789");
        p.add("smartgn.internal.token", () -> "isolated-database-service-key-0123456789");
        p.add("smartgn.delivery.key", () -> "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    }

    IdentityOperations.Account pending() {
        UUID order = UUID.randomUUID();
        return operations.provision(
                new IdentityOperations.Purchase(
                        UUID.randomUUID(),
                        order,
                        "db-" + order + "@example.test",
                        "Database",
                        "Fixture",
                        true));
    }

    String activation(UUID account, boolean expired) {
        String plain = UUID.randomUUID().toString();
        String hash;
        try {
            hash =
                    java.util.HexFormat.of()
                            .formatHex(
                                    java.security.MessageDigest.getInstance("SHA-256")
                                            .digest(plain.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        db.update(
                "INSERT INTO iam.one_time_tokens(token_id,account_id,token_hash,purpose,expires_at)"
                        + " VALUES (?,?,?,'ACTIVATION',now()+(? * interval '1 minute'))",
                UUID.randomUUID(),
                account,
                hash,
                expired ? -1 : 10);
        return plain;
    }

    @Autowired com.smartgn.iam.auth.application.port.in.PasswordRecoveryUseCase recovery;

    @Test
    void simultaneousRecoveryRequestsLeaveOnlyOneCurrentLink() throws Exception {
        var a = pending();
        operations.activate(activation(a.accountId(), false), "OldPassword123");
        try (var executor = Executors.newFixedThreadPool(2)) {
            CountDownLatch gate = new CountDownLatch(1);
            Callable<Void> request =
                    () -> {
                        gate.await();
                        recovery.requestRecovery(a.email());
                        return null;
                    };
            var first = executor.submit(request);
            var second = executor.submit(request);
            gate.countDown();
            first.get(15, TimeUnit.SECONDS);
            second.get(15, TimeUnit.SECONDS);
        }
        assertEquals(
                1,
                db.queryForObject(
                        "SELECT count(*) FROM iam.one_time_tokens WHERE account_id=? AND"
                                + " purpose='RECOVERY' AND used_at IS NULL",
                        Integer.class,
                        a.accountId()));
    }

    @Test
    void confirmedPurchaseIsIdempotentAndDoesNotStorePlaintextCredentials() {
        UUID event = UUID.randomUUID(), order = UUID.randomUUID();
        var p =
                new IdentityOperations.Purchase(
                        event, order, "order-" + order + "@example.test", "First", "Last", true);
        var first = operations.provision(p);
        assertEquals(first, operations.provision(p));
        assertEquals("PENDING_ACTIVATION", first.status());
        assertEquals(
                0,
                db.queryForObject(
                        "SELECT count(*) FROM iam.password_credentials WHERE account_id=?",
                        Integer.class,
                        first.accountId()));
        assertThrows(
                org.springframework.web.server.ResponseStatusException.class,
                () ->
                        operations.provision(
                                new IdentityOperations.Purchase(
                                        event,
                                        UUID.randomUUID(),
                                        p.email(),
                                        "First",
                                        "Last",
                                        true)));
        assertThrows(
                org.springframework.web.server.ResponseStatusException.class,
                () ->
                        operations.provision(
                                new IdentityOperations.Purchase(
                                        UUID.randomUUID(),
                                        UUID.randomUUID(),
                                        "unverified@example.test",
                                        "First",
                                        "Last",
                                        false)));
    }

    @Test
    void expiredActivationAndDisabledAccountNeverAuthorize() {
        var a = pending();
        assertThrows(
                org.springframework.web.server.ResponseStatusException.class,
                () -> operations.activate(activation(a.accountId(), true), "NewPassword123"));
        String token = activation(a.accountId(), false);
        operations.activate(token, "NewPassword123");
        String jwtToken = jwt.generateToken(accounts.findById(a.accountId()).orElseThrow());
        assertTrue(jwt.validate(jwtToken).isPresent());
        db.update(
                "UPDATE iam.user_accounts SET account_status='DISABLED' WHERE account_id=?",
                a.accountId());
        assertTrue(jwt.validate(jwtToken).isEmpty());
    }

    @Test
    void concurrentActivationConsumesTheTokenOnce() throws Exception {
        var a = pending();
        String token = activation(a.accountId(), false);
        try (var executor = Executors.newFixedThreadPool(2)) {
            CountDownLatch gate = new CountDownLatch(1);
            Callable<Boolean> activate =
                    () -> {
                        gate.await();
                        try {
                            operations.activate(token, "NewPassword123");
                            return true;
                        } catch (org.springframework.web.server.ResponseStatusException denied) {
                            return false;
                        }
                    };
            var first = executor.submit(activate);
            var second = executor.submit(activate);
            gate.countDown();
            assertNotEquals(first.get(15, TimeUnit.SECONDS), second.get(15, TimeUnit.SECONDS));
        }
        assertEquals(
                1,
                db.queryForObject(
                        "SELECT count(*) FROM iam.password_credentials WHERE account_id=?",
                        Integer.class,
                        a.accountId()));
    }

    @Test
    void changingPasswordInvalidatesSessionsAndRequiresTheCurrentPassword() {
        var a = pending();
        operations.activate(activation(a.accountId(), false), "OldPassword123");
        String token = jwt.generateToken(accounts.findById(a.accountId()).orElseThrow());
        assertThrows(
                org.springframework.web.server.ResponseStatusException.class,
                () -> operations.changePassword(a.accountId(), "incorrect", "NewPassword123"));
        assertTrue(jwt.validate(token).isPresent());
        operations.changePassword(a.accountId(), "OldPassword123", "NewPassword123");
        assertTrue(jwt.validate(token).isEmpty());
        assertEquals(1, operations.context(a.accountId()).sessionVersion());
    }

    @Test
    void subusersHaveNoDefaultGrantsAndCannotDelegate() {
        var a = pending();
        operations.activate(activation(a.accountId(), false), "OldPassword123");
        var sub =
                operations.createSubuser(
                        a.accountId(),
                        "sub-" + UUID.randomUUID() + "@example.test",
                        "Sub",
                        "Fixture");
        assertEquals("DELEGATED", sub.accountKind());
        assertEquals(a.accountId(), sub.principalAccountId());
        assertTrue(operations.meterGrants(a.accountId()).isEmpty());
        assertThrows(
                org.springframework.web.server.ResponseStatusException.class,
                () ->
                        operations.createSubuser(
                                sub.accountId(), "denied@example.test", "No", "Access"));
        assertEquals(
                0,
                db.queryForObject(
                        "SELECT count(*) FROM iam.meter_permission_grants g JOIN iam.delegations d"
                                + " USING(delegation_id) WHERE d.delegate_account_id=?",
                        Integer.class,
                        sub.accountId()));
    }
}
