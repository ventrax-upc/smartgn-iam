package com.ventrax.iam.auth.infrastructure.persistence;

import com.ventrax.iam.auth.application.port.out.OneTimeTokenRepository;
import com.ventrax.iam.auth.domain.model.OneTimeToken;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.*;
import java.util.*;

@Repository
public class JdbcOneTimeTokenRepository implements OneTimeTokenRepository {
    private final JdbcTemplate db;

    public JdbcOneTimeTokenRepository(JdbcTemplate db) {
        this.db = db;
    }

    public OneTimeToken save(OneTimeToken t) {
        db.update(
                "INSERT INTO"
                    + " iam.one_time_tokens(token_id,account_id,token_hash,purpose,created_at,expires_at,used_at)"
                    + " VALUES (?,?,?,'RECOVERY',?,?,?) ON CONFLICT(token_id) DO UPDATE SET"
                    + " used_at=EXCLUDED.used_at",
                t.getId(),
                t.getAccountId(),
                t.getTokenHash(),
                Timestamp.from(t.getCreatedAt()),
                Timestamp.from(t.getExpiresAt()),
                t.getUsedAt() == null ? null : Timestamp.from(t.getUsedAt()));
        return t;
    }

    public Optional<OneTimeToken> findByTokenHash(String hash) {
        // Account-first ordering also serializes password changes and simultaneous recovery links.
        db.queryForList(
                "SELECT a.account_id FROM iam.user_accounts a JOIN iam.one_time_tokens t ON"
                    + " t.account_id=a.account_id WHERE t.token_hash=? AND t.purpose='RECOVERY' FOR"
                    + " UPDATE OF a",
                hash);

        return db
                .query(
                        "SELECT * FROM iam.one_time_tokens WHERE token_hash=? AND"
                                + " purpose='RECOVERY' FOR UPDATE",
                        (s, n) ->
                                OneTimeToken.restore(
                                        s.getObject("token_id", UUID.class),
                                        s.getObject("account_id", UUID.class),
                                        s.getString("token_hash"),
                                        s.getTimestamp("created_at").toInstant(),
                                        s.getTimestamp("expires_at").toInstant(),
                                        s.getTimestamp("used_at") == null
                                                ? null
                                                : s.getTimestamp("used_at").toInstant()),
                        hash)
                .stream()
                .findFirst();
    }

    @Transactional
    public void invalidatePending(UUID id, Instant now) {
        db.update(
                "UPDATE iam.one_time_tokens SET used_at=? WHERE account_id=? AND purpose='RECOVERY'"
                        + " AND used_at IS NULL",
                Timestamp.from(now),
                id);
    }
}
