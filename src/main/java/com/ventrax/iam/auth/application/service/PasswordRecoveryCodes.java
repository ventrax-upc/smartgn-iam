package com.ventrax.iam.auth.application.service;

import com.ventrax.iam.auth.application.port.out.AccountRepository;
import com.ventrax.iam.auth.application.port.out.OneTimeTokenRepository;
import com.ventrax.iam.auth.application.port.out.ResetTokenCodec;
import com.ventrax.iam.auth.domain.model.OneTimeToken;
import com.ventrax.iam.auth.infrastructure.notification.SecureDeliveryQueue;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class PasswordRecoveryCodes {
    private final JdbcTemplate db;
    private final AccountRepository accounts;
    private final OneTimeTokenRepository tokens;
    private final ResetTokenCodec codec;
    private final SecureDeliveryQueue delivery;
    private final Clock clock;
    private final byte[] key;
    private final SecureRandom random = new SecureRandom();

    public PasswordRecoveryCodes(JdbcTemplate db, AccountRepository accounts, OneTimeTokenRepository tokens,
            ResetTokenCodec codec, SecureDeliveryQueue delivery, Clock clock,
            @Value("${smartgn.internal.token}") String secret) {
        this.db = db;
        this.accounts = accounts;
        this.tokens = tokens;
        this.codec = codec;
        this.delivery = delivery;
        this.clock = clock;
        this.key = secret.getBytes(StandardCharsets.UTF_8);
    }

    @Transactional
    public UUID send(String address) {
        String email = address.trim().toLowerCase(Locale.ROOT);
        var account = accounts.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Email is not registered"));
        if (!"ACTIVE".equals(account.getStatus())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Account is not active");
        }
        if (!delivery.isConfigured()) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Email delivery is not configured");
        }
        db.queryForList("SELECT account_id FROM iam.user_accounts WHERE account_id=? FOR UPDATE", account.getId());
        UUID challenge = UUID.randomUUID();
        String code = String.format(Locale.ROOT, "%06d", random.nextInt(1_000_000));
        int saved = db.update("""
                INSERT INTO iam.password_recovery_codes(account_id,challenge_id,code_hash,expires_at)
                VALUES (?,?,?,now()+interval '10 minutes')
                ON CONFLICT (account_id) DO UPDATE SET challenge_id=excluded.challenge_id,
                   code_hash=excluded.code_hash, expires_at=excluded.expires_at, attempts=0, verified_at=NULL
                WHERE iam.password_recovery_codes.expires_at <= now()+interval '9 minutes'
                """, account.getId(), challenge, hash(challenge, code));
        if (saved == 0) throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Wait before requesting a new code");
        tokens.invalidatePending(account.getId(), clock.instant());
        delivery.queue(Map.of("purpose", "RECOVERY_CODE", "email", email, "code", code,
                "challengeId", challenge, "expiresAt", clock.instant().plus(10, ChronoUnit.MINUTES).toString()));
        return challenge;
    }

    @Transactional
    public String verify(UUID challenge, String code) {
        db.queryForList("""
                SELECT a.account_id FROM iam.user_accounts a JOIN iam.password_recovery_codes c
                    ON c.account_id=a.account_id WHERE c.challenge_id=? FOR UPDATE OF a
                """, challenge);
        var rows = db.queryForList("""
                SELECT account_id,code_hash FROM iam.password_recovery_codes
                WHERE challenge_id=? AND expires_at>now() AND attempts<5 AND verified_at IS NULL FOR UPDATE
                """, challenge);
        if (rows.isEmpty()) return null;
        String expected = (String) rows.getFirst().get("code_hash");
        if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                hash(challenge, code).getBytes(StandardCharsets.UTF_8))) {
            db.update("UPDATE iam.password_recovery_codes SET attempts=attempts+1 WHERE challenge_id=?", challenge);
            return null;
        }
        UUID account = (UUID) rows.getFirst().get("account_id");
        String proof = codec.generateToken();
        var now = clock.instant();
        tokens.invalidatePending(account, now);
        tokens.save(OneTimeToken.create(account, codec.hash(proof), now, now.plus(10, ChronoUnit.MINUTES)));
        db.update("UPDATE iam.password_recovery_codes SET verified_at=now() WHERE challenge_id=?", challenge);
        return proof;
    }

    private String hash(UUID challenge, String code) {
        try {
            var mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal((challenge + ":" + code).getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.GeneralSecurityException failure) {
            throw new IllegalStateException("Password recovery code unavailable", failure);
        }
    }
}
