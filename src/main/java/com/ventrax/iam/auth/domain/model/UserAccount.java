package com.ventrax.iam.auth.domain.model;

import java.time.Instant;
import java.util.UUID;

public class UserAccount {

    private UUID id = UUID.randomUUID();

    private String email;
    private String status = "ACTIVE";
    private String kind = "PRINCIPAL";
    private long sessionVersion;

    private PasswordCredential credential;

    private Role role;

    private Instant createdAt;

    protected UserAccount() {
        // Reconstruction constructor
    }

    private UserAccount(String email, String passwordHash, Role role) {
        this.email = email;
        this.credential =
                passwordHash == null
                        ? null
                        : new PasswordCredential(UUID.randomUUID(), passwordHash, Instant.now());
        this.role = role;
        this.createdAt = Instant.now();
    }

    /** Reconstruction helper. Public registration is intentionally unavailable. */
    public static UserAccount create(String email, String passwordHash, Role role) {
        return new UserAccount(email, passwordHash, role);
    }

    public void changePasswordHash(String newHash) {
        this.credential =
                new PasswordCredential(
                        credential == null ? UUID.randomUUID() : credential.credentialId(),
                        newHash,
                        Instant.now());
    }

    public static UserAccount restore(
            UUID id,
            String email,
            String hash,
            Role role,
            Instant created,
            String status,
            String kind,
            long version,
            UUID credentialId,
            Instant credentialUpdatedAt) {
        UserAccount c = new UserAccount(email, hash, role);
        c.id = id;
        c.createdAt = created;
        c.status = status;
        c.kind = kind;
        c.sessionVersion = version;
        c.credential =
                hash == null
                        ? null
                        : new PasswordCredential(credentialId, hash, credentialUpdatedAt);
        return c;
    }

    public String getStatus() {
        return status;
    }

    public String getKind() {
        return kind;
    }

    public long getSessionVersion() {
        return sessionVersion;
    }

    public UUID getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public String getPasswordHash() {
        return credential == null ? null : credential.passwordHash();
    }

    public Role getRole() {
        return role;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
