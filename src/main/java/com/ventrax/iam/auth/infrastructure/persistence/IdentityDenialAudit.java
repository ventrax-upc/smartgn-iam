package com.ventrax.iam.auth.infrastructure.persistence;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.*;

import java.util.UUID;

@Component
public class IdentityDenialAudit {
    private final JdbcTemplate db;

    public IdentityDenialAudit(JdbcTemplate db) {
        this.db = db;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(UUID actor, UUID resource) {
        db.update(
                "INSERT INTO"
                        + " iam.identity_audit(audit_id,actor_id,action,resource_id,correlation_id)"
                        + " VALUES (?,?,'GRANT_ACCESS_DENIED',?,?)",
                UUID.randomUUID(),
                actor,
                resource,
                org.slf4j.MDC.get("correlationId") == null
                        ? UUID.randomUUID()
                        : UUID.fromString(org.slf4j.MDC.get("correlationId")));
    }
}
