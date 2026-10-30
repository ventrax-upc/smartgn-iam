package com.ventrax.iam.auth.domain.model;

import java.time.Instant;
import java.util.UUID;

/** Password reset request. Only the token hash is stored, never the token itself. */
public class OneTimeToken {

    public enum Purpose {
        ACTIVATION,
        RECOVERY
    }

    private Purpose purpose = Purpose.RECOVERY;

    public Purpose getPurpose() {
        return purpose;
    }

    public boolean canConsume(Purpose expected, Instant now) {
        return purpose == expected && isValid(now);
    }

    private UUID id = UUID.randomUUID();

    private UUID accountId;

    private String tokenHash;

    private Instant createdAt;

    private Instant expiresAt;

    private Instant usedAt;

    protected OneTimeToken() {
        // Reconstruction constructor
    }

    private OneTimeToken(UUID accountId, String tokenHash, Instant createdAt, Instant expiresAt) {
        this.accountId = accountId;
        this.tokenHash = tokenHash;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
    }

    public static OneTimeToken create(
            UUID accountId, String tokenHash, Instant createdAt, Instant expiresAt) {
        return new OneTimeToken(accountId, tokenHash, createdAt, expiresAt);
    }

    public boolean isValid(Instant now) {
        return usedAt == null && now.isBefore(expiresAt);
    }

    public void markUsed(Instant now) {
        this.usedAt = now;
    }

    public static OneTimeToken restore(
            UUID id, UUID account, String hash, Instant created, Instant expires, Instant used) {
        OneTimeToken t = new OneTimeToken(account, hash, created, expires);
        t.id = id;
        t.usedAt = used;
        return t;
    }

    public static OneTimeToken restore(
            UUID id,
            UUID account,
            String hash,
            Instant created,
            Instant expires,
            Instant used,
            Purpose purpose) {
        OneTimeToken token = restore(id, account, hash, created, expires, used);
        token.purpose = java.util.Objects.requireNonNull(purpose);
        return token;
    }

    public UUID getId() {
        return id;
    }

    public UUID getAccountId() {
        return accountId;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getUsedAt() {
        return usedAt;
    }
}
