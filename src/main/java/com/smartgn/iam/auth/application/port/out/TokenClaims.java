package com.smartgn.iam.auth.application.port.out;

import com.smartgn.iam.auth.domain.model.Role;

import java.util.UUID;

/** Authenticated user data extracted from a valid token. */
public record TokenClaims(UUID accountId, String email, Role role) {}
