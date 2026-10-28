package com.smartgn.iam.auth.domain.model;

import java.time.Instant;
import java.util.UUID;

public record PasswordCredential(UUID credentialId, String passwordHash, Instant updatedAt) {
    @Override
    public String toString() {
        return "PasswordCredential[credentialId=" + credentialId + ", passwordHash=REDACTED]";
    }
}
