package com.smartgn.iam.auth.infrastructure.persistence;

import com.smartgn.iam.auth.application.port.out.AccountRepository;
import com.smartgn.iam.auth.domain.model.*;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.*;

@Repository
public class JdbcAccountRepository implements AccountRepository {
    private final JdbcTemplate db;

    public JdbcAccountRepository(JdbcTemplate db) {
        this.db = db;
    }

    public boolean existsByEmail(String email) {
        return Boolean.TRUE.equals(
                db.queryForObject(
                        "SELECT EXISTS(SELECT 1 FROM iam.user_accounts WHERE email=?)",
                        Boolean.class,
                        email));
    }

    private Optional<UserAccount> find(String condition, Object value) {
        return db
                .query(
                        "SELECT a.*,c.password_hash,c.credential_id,c.updated_at,CASE WHEN"
                            + " a.account_kind='DELEGATED' AND NOT EXISTS(SELECT 1 FROM"
                            + " iam.delegations d JOIN iam.user_accounts p ON"
                            + " p.account_id=d.principal_account_id WHERE"
                            + " d.delegate_account_id=a.account_id AND d.active AND"
                            + " p.account_status='ACTIVE') THEN 'DISABLED' ELSE a.account_status"
                            + " END AS effective_status FROM iam.user_accounts a LEFT JOIN"
                            + " iam.password_credentials c USING(account_id) WHERE "
                                + condition
                                + (org.springframework.transaction.support
                                                        .TransactionSynchronizationManager
                                                        .isActualTransactionActive()
                                                && !org.springframework.transaction.support
                                                        .TransactionSynchronizationManager
                                                        .isCurrentTransactionReadOnly()
                                        ? " FOR UPDATE OF a"
                                        : ""),
                        (s, n) ->
                                UserAccount.restore(
                                        s.getObject("account_id", UUID.class),
                                        s.getString("email"),
                                        s.getString("password_hash"),
                                        Role.valueOf(s.getString("role")),
                                        s.getTimestamp("created_at").toInstant(),
                                        s.getString("effective_status"),
                                        s.getString("account_kind"),
                                        s.getLong("session_version"),
                                        s.getObject("credential_id", UUID.class),
                                        s.getTimestamp("updated_at") == null
                                                ? null
                                                : s.getTimestamp("updated_at").toInstant()),
                        value)
                .stream()
                .findFirst();
    }

    public Optional<UserAccount> findById(UUID id) {
        return find("a.account_id=?", id);
    }

    public Optional<UserAccount> findByEmail(String email) {
        return find("a.email=?", email);
    }

    public UserAccount save(UserAccount c) {
        var old = findById(c.getId());
        if (old.isPresent()
                && !java.util.Objects.equals(old.get().getPasswordHash(), c.getPasswordHash())) {
            db.update(
                    "UPDATE iam.user_accounts SET session_version=session_version+1 WHERE"
                            + " account_id=?",
                    c.getId());
            db.update(
                    "INSERT INTO iam.domain_outbox(event_id,event_type,aggregate_id,correlation_id)"
                            + " VALUES (?,'CredentialsChanged',?,?)",
                    UUID.randomUUID(),
                    c.getId(),
                    org.slf4j.MDC.get("correlationId") == null
                            ? UUID.randomUUID()
                            : UUID.fromString(org.slf4j.MDC.get("correlationId")));
        }
        db.update(
                "INSERT INTO"
                    + " iam.user_accounts(account_id,email,role,account_kind,account_status,created_at)"
                    + " VALUES (?,?,?,?,?,?) ON CONFLICT(account_id) DO UPDATE SET"
                    + " email=EXCLUDED.email,role=EXCLUDED.role",
                c.getId(),
                c.getEmail(),
                c.getRole().name(),
                c.getKind(),
                c.getStatus(),
                java.sql.Timestamp.from(c.getCreatedAt()));
        db.update(
                "INSERT INTO iam.password_credentials(credential_id,account_id,password_hash)"
                        + " VALUES (?,?,?) ON CONFLICT(account_id) DO UPDATE SET"
                        + " password_hash=EXCLUDED.password_hash,updated_at=now()",
                UUID.randomUUID(),
                c.getId(),
                c.getPasswordHash());
        return c;
    }
}
