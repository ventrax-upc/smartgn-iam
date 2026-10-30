package com.ventrax.iam.auth.infrastructure.security;

import com.ventrax.iam.auth.application.port.out.TokenClaims;
import com.ventrax.iam.auth.application.port.out.TokenProvider;
import com.ventrax.iam.auth.domain.model.Role;
import com.ventrax.iam.auth.domain.model.UserAccount;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import javax.crypto.SecretKey;

@Component
public class JwtProvider implements TokenProvider {

    static final String ISSUER = "smartgn-iam-service";

    private com.ventrax.iam.auth.application.port.out.AccountRepository accounts;

    @org.springframework.beans.factory.annotation.Autowired
    public void liveAccounts(com.ventrax.iam.auth.application.port.out.AccountRepository accounts) {
        this.accounts = accounts;
    }

    private final SecretKey key;
    private final Duration expiration;

    public JwtProvider(
            @Value("${smartgn.security.jwt.secret}") String secret,
            @Value("${smartgn.security.jwt.expiration-minutes}") long expirationMinutes) {
        // Fails at startup if the key is shorter than 256 bits (32 characters)
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expiration = Duration.ofMinutes(expirationMinutes);
    }

    @Override
    public String generateToken(UserAccount account) {
        Instant now = Instant.now();
        return Jwts.builder()
                .issuer(ISSUER)
                .subject(account.getId().toString())
                .audience()
                .add("smartgn-api")
                .and()
                .claim("accountId", account.getId().toString())
                .claim("email", account.getEmail())
                .claim("role", account.getRole().name())
                .claim("accountKind", account.getKind())
                .claim("sessionVersion", account.getSessionVersion())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(expiration)))
                .signWith(key)
                .compact();
    }

    @Override
    public Optional<TokenClaims> validate(String token) {
        try {
            Claims claims =
                    Jwts.parser()
                            .verifyWith(key)
                            .requireIssuer(ISSUER)
                            .build()
                            .parseSignedClaims(token)
                            .getPayload();
            if (claims.getSubject() == null
                    || claims.get("role", String.class) == null
                    || claims.getExpiration() == null
                    || claims.getIssuedAt() == null
                    || claims.getIssuedAt().toInstant().isAfter(Instant.now().plusSeconds(60))
                    || claims.getAudience() == null
                    || !claims.getAudience().contains("smartgn-api")
                    || !claims.getSubject().equals(claims.get("accountId", String.class)))
                return Optional.empty();
            if (accounts != null) {
                var account = accounts.findById(UUID.fromString(claims.getSubject()));
                if (account.isEmpty()
                        || !"ACTIVE".equals(account.get().getStatus())
                        || !account.get().getRole().name().equals(claims.get("role", String.class))
                        || claims.get("sessionVersion", Number.class) == null
                        || account.get().getSessionVersion()
                                != claims.get("sessionVersion", Number.class).longValue())
                    return Optional.empty();
            }
            return Optional.of(
                    new TokenClaims(
                            UUID.fromString(claims.get("accountId", String.class)),
                            claims.get("email", String.class),
                            Role.valueOf(claims.get("role", String.class))));
        } catch (JwtException | IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
