package com.ventrax.iam.auth.domain.model;

public enum Role {
    USER,
    SUPERADMIN;

    /** Identifies the USER role for principal and delegated accounts. */
    public boolean isPublicRole() {
        return this != SUPERADMIN;
    }
}
