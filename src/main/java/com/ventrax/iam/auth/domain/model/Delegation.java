package com.ventrax.iam.auth.domain.model;

import java.util.UUID;

public record Delegation(
        UUID delegationId, UUID principalAccountId, UUID delegateAccountId, boolean active) {
    public boolean belongsTo(UUID principal) {
        return active && principalAccountId.equals(principal);
    }
}
