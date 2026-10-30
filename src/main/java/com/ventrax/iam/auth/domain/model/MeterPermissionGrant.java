package com.ventrax.iam.auth.domain.model;

import java.time.Instant;
import java.util.UUID;

public record MeterPermissionGrant(
        UUID grantId, UUID meterId, String function, Instant grantedAt, Instant revokedAt) {
    public MeterPermissionGrant {
        IdentityPolicy.functions(java.util.Set.of(function));
    }

    public boolean active() {
        return revokedAt == null;
    }
}
