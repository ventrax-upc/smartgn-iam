package com.smartgn.iam.auth.interfaces.rest;

import com.smartgn.iam.auth.application.port.in.IdentityOperations;
import com.smartgn.iam.auth.application.port.out.TokenClaims;
import com.smartgn.iam.auth.infrastructure.security.JwtProvider;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;

import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.*;

@RestController
@Tag(name = "Activation and delegated access")
public class IdentityController {
    private final IdentityOperations identities;
    private final JwtProvider jwt;

    public IdentityController(IdentityOperations identities, JwtProvider jwt) {
        this.identities = identities;
        this.jwt = jwt;
    }

    public record Activation(
            @NotBlank String activationToken,
            @NotBlank @Size(min = 8, max = 72) String newPassword) {}

    public record Change(
            @NotBlank String currentPassword,
            @NotBlank @Size(min = 8, max = 72) String newPassword) {}

    public record Subuser(
            @NotBlank @Email @Size(max = 254) String email,
            @NotBlank @Size(max = 100) String firstName,
            @NotBlank @Size(max = 100) String lastName) {}

    public record Grants(@NotNull UUID meterId, @NotNull Set<String> permissions) {}

    public record ConfirmedPurchase(
            @NotNull UUID eventId,
            @NotNull UUID purchaseOrderId,
            @NotBlank @Email @Size(max = 254) String email,
            @NotBlank @Size(max = 100) String firstName,
            @NotBlank @Size(max = 100) String lastName,
            boolean confirmed) {}

    public record Session(@NotBlank String token) {}

    public record Check(
            @NotNull UUID accountId,
            @NotNull UUID meterId,
            @NotBlank String function,
            boolean requiresPro) {}

    @io.swagger.v3.oas.annotations.security.SecurityRequirements
    @PostMapping("/api/v1/auth/activate-password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(
            summary = "Activate a pending principal or delegated account with a single-use token")
    public void activate(@Valid @RequestBody Activation r) {
        identities.activate(r.activationToken(), r.newPassword());
    }

    @PostMapping("/api/v1/auth/change-password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Change the current password and invalidate existing sessions")
    public void change(@AuthenticationPrincipal TokenClaims me, @Valid @RequestBody Change r) {
        identities.changePassword(me.accountId(), r.currentPassword(), r.newPassword());
    }

    @PostMapping("/api/v1/subusers")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Create a delegated USER identity without initial permissions")
    public IdentityOperations.Account subuser(
            @AuthenticationPrincipal TokenClaims me, @Valid @RequestBody Subuser r) {
        return identities.createSubuser(me.accountId(), r.email(), r.firstName(), r.lastName());
    }

    @GetMapping("/api/v1/subusers")
    @Operation(summary = "List the principal account's subusers")
    public List<IdentityOperations.Account> subusers(@AuthenticationPrincipal TokenClaims me) {
        return identities.subusers(me.accountId());
    }

    @PutMapping("/api/v1/subusers/{subuserId}/grants")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Replace one meter's function grants, preserving other meters")
    public void grants(
            @AuthenticationPrincipal TokenClaims me,
            @PathVariable UUID subuserId,
            @Valid @RequestBody Grants r) {
        identities.grants(me.accountId(), subuserId, r.meterId(), r.permissions());
    }

    @GetMapping("/api/v1/subusers/{subuserId}/grants/{meterId}")
    @Operation(summary = "Get current function grants on a meter")
    public Set<String> grants(
            @AuthenticationPrincipal TokenClaims me,
            @PathVariable UUID subuserId,
            @PathVariable UUID meterId) {
        return identities.grants(me.accountId(), subuserId, meterId);
    }

    @DeleteMapping("/api/v1/subusers/{subuserId}/grants/{meterId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Revoke all grants on one meter")
    public void revoke(
            @AuthenticationPrincipal TokenClaims me,
            @PathVariable UUID subuserId,
            @PathVariable UUID meterId) {
        identities.grants(me.accountId(), subuserId, meterId, Set.of());
    }

    @io.swagger.v3.oas.annotations.security.SecurityRequirement(name = "serviceAuth")
    @PostMapping("/internal/v1/accounts/purchase-confirmations")
    @Operation(
            summary =
                    "Provision an account after a verified initial purchase; controlled service"
                            + " input")
    public IdentityOperations.Account provision(@Valid @RequestBody ConfirmedPurchase p) {
        return identities.provision(
                new IdentityOperations.Purchase(
                        p.eventId(),
                        p.purchaseOrderId(),
                        p.email(),
                        p.firstName(),
                        p.lastName(),
                        p.confirmed()));
    }

    @io.swagger.v3.oas.annotations.security.SecurityRequirement(name = "serviceAuth")
    @PostMapping("/internal/v1/sessions/introspect")
    @Operation(summary = "Check current account state and session version")
    public IdentityOperations.Account introspect(@Valid @RequestBody Session session) {
        return jwt.validate(session.token())
                .map(c -> identities.context(c.accountId()))
                .orElseThrow(
                        () ->
                                new ResponseStatusException(
                                        HttpStatus.UNAUTHORIZED, "Invalid session"));
    }

    @io.swagger.v3.oas.annotations.security.SecurityRequirement(name = "serviceAuth")
    @GetMapping("/internal/v1/accounts/{id}/grants")
    public Map<UUID, Set<String>> meterGrants(@PathVariable UUID id) {
        return identities.meterGrants(id);
    }

    @io.swagger.v3.oas.annotations.security.SecurityRequirement(name = "serviceAuth")
    @GetMapping("/internal/v1/accounts/{id}")
    public IdentityOperations.Account context(@PathVariable UUID id) {
        return identities.context(id);
    }

    @io.swagger.v3.oas.annotations.security.SecurityRequirement(name = "serviceAuth")
    @PostMapping("/internal/v1/authorizations/check")
    @Operation(
            summary =
                    "Check a current meter/function grant; entitlement checked separately when"
                            + " required")
    public Map<String, Boolean> check(@Valid @RequestBody Check c) {
        return Map.of(
                "allowed",
                identities.authorize(c.accountId(), c.meterId(), c.function(), c.requiresPro()));
    }
}
