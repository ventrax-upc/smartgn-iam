package com.ventrax.iam.auth.interfaces.rest;

import com.ventrax.iam.auth.application.port.in.SignInResult;
import com.ventrax.iam.auth.domain.model.Role;

import java.util.UUID;

public record AuthenticatedAccountResource(
        UUID id, String email, Role role, String accountKind, String token) {
    public static AuthenticatedAccountResource from(SignInResult r) {
        return new AuthenticatedAccountResource(
                r.account().getId(),
                r.account().getEmail(),
                r.account().getRole(),
                r.account().getKind(),
                r.token());
    }
}
