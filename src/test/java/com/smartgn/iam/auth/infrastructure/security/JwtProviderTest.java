package com.smartgn.iam.auth.infrastructure.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.smartgn.iam.auth.application.port.out.TokenClaims;
import com.smartgn.iam.auth.domain.model.Role;
import com.smartgn.iam.auth.domain.model.UserAccount;

import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;
import java.util.UUID;

class JwtProviderTest {

    @Test
    void rejectsMissingAudienceWrongIssuerAndInconsistentSubjects() {
        var provider = new JwtProvider(SECRET, 15);
        var key =
                io.jsonwebtoken.security.Keys.hmacShaKeyFor(
                        SECRET.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        UUID id = UUID.randomUUID();
        for (int scenario = 0; scenario < 4; scenario++) {
            var builder =
                    io.jsonwebtoken.Jwts.builder()
                            .issuer(scenario == 1 ? "wrong" : "smartgn-iam-service")
                            .subject(scenario == 2 ? UUID.randomUUID().toString() : id.toString())
                            .claim("accountId", id.toString())
                            .claim("role", "USER")
                            .issuedAt(java.util.Date.from(java.time.Instant.now()))
                            .expiration(
                                    java.util.Date.from(java.time.Instant.now().plusSeconds(60)));
            if (scenario != 0)
                builder.audience().add(scenario == 3 ? "wrong-audience" : "smartgn-api").and();
            assertTrue(provider.validate(builder.signWith(key).compact()).isEmpty());
        }
    }

    private static final String SECRET = "test-secret-test-secret-test-secret-123456";
    private static final String OTHER_SECRET = "other-secret-other-secret-other-secret-123";

    private UserAccount accountWithId() {
        UserAccount account = UserAccount.create("user@example.test", "HASH", Role.USER);
        ReflectionTestUtils.setField(account, "id", UUID.randomUUID());
        return account;
    }

    @Test
    void generatedTokenValidatesAndRetainsClaims() {
        JwtProvider provider = new JwtProvider(SECRET, 15);
        UserAccount account = accountWithId();

        Optional<TokenClaims> claims = provider.validate(provider.generateToken(account));

        assertTrue(claims.isPresent());
        assertEquals(account.getId(), claims.get().accountId());
        assertEquals("user@example.test", claims.get().email());
        assertEquals(Role.USER, claims.get().role());
    }

    @Test
    void rejectsExpiredToken() {
        JwtProvider provider = new JwtProvider(SECRET, -1);

        assertTrue(provider.validate(provider.generateToken(accountWithId())).isEmpty());
    }

    @Test
    void rejectsTokenSignedWithAnotherKey() {
        String token = new JwtProvider(OTHER_SECRET, 15).generateToken(accountWithId());

        assertTrue(new JwtProvider(SECRET, 15).validate(token).isEmpty());
    }

    @Test
    void rejectsTextThatIsNotAToken() {
        assertTrue(new JwtProvider(SECRET, 15).validate("esto-no-es-un-jwt").isEmpty());
    }
}
