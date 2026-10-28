package com.smartgn.iam.auth.domain.model;

import java.util.Set;

public final class IdentityPolicy {
    private IdentityPolicy() {}

    public static final Set<String> FUNCTIONS =
            Set.of(
                    "VIEW_CONSUMPTION",
                    "VIEW_HISTORY",
                    "VIEW_ALERTS",
                    "USE_REPORTS",
                    "USE_TICKETS",
                    "USE_VISITS");

    public static boolean principal(String role, String kind, String status) {
        return "USER".equals(role) && "PRINCIPAL".equals(kind) && "ACTIVE".equals(status);
    }

    public static void functions(Set<String> functions) {
        if (functions == null || !FUNCTIONS.containsAll(functions))
            throw new IllegalArgumentException(
                    "Only the six documented meter functions can be delegated");
    }
}
