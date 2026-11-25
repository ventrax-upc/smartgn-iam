package com.ventrax.iam.auth.interfaces.rest;

import com.ventrax.iam.auth.application.port.in.PasswordRecoveryUseCase;
import com.ventrax.iam.auth.application.port.in.SignInCommand;
import com.ventrax.iam.auth.application.port.in.SignInUseCase;
import com.ventrax.iam.auth.application.port.out.TokenClaims;
import com.ventrax.iam.auth.application.port.out.TokenProvider;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.server.ResponseStatusException;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;

import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Authentication", description = "Authentication and password recovery")
public class AuthController {

    private final TokenProvider tokenProvider;
    private final SignInUseCase signInUseCase;
    private final PasswordRecoveryUseCase passwordRecoveryUseCase;

    public AuthController(
            SignInUseCase signInUseCase, PasswordRecoveryUseCase passwordRecoveryUseCase,
            TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
        this.signInUseCase = signInUseCase;
        this.passwordRecoveryUseCase = passwordRecoveryUseCase;
    }

    @PostMapping("/sign-in")
    @SecurityRequirements
    @Operation(
            summary = "Sign in",
            description =
                    "Validates the credentials and returns a signed JWT with the claims accountId,"
                            + " email, role, accountKind and sessionVersion.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Authentication successful"),
        @ApiResponse(responseCode = "400", description = "Invalid data"),
        @ApiResponse(responseCode = "401", description = "Invalid email or password")
    })
    public ResponseEntity<AuthenticatedAccountResource> signIn(
            @Valid @RequestBody SignInResource resource) {
        var result =
                signInUseCase.execute(new SignInCommand(resource.email(), resource.password()));
        return ResponseEntity.ok(AuthenticatedAccountResource.from(result));
    }

    public record RenewedSession(String token) {}

    @PostMapping("/renew-session")
    @Operation(summary = "Renew an active session")
    public ResponseEntity<RenewedSession> renewSession(@AuthenticationPrincipal TokenClaims claims) {
        String token = tokenProvider.renew(claims)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Session expired"));
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(new RenewedSession(token));
    }

    @PostMapping("/forgot-password")
    @SecurityRequirements
    @Operation(
            summary = "Request password recovery",
            description =
                    "Requests a temporary reset link for a registered email. Delivery requires an"
                            + " configured notification delivery adapter. The response is the"
                            + " same whether or not the account exists.")
    @ApiResponses({
        @ApiResponse(responseCode = "202", description = "Request received"),
        @ApiResponse(responseCode = "400", description = "Email with invalid format")
    })
    public ResponseEntity<MessageResource> forgotPassword(
            @Valid @RequestBody ForgotPasswordResource resource) {
        passwordRecoveryUseCase.requestRecovery(resource.email());
        return ResponseEntity.accepted()
                .body(
                        new MessageResource(
                                "If the email is registered, you will receive instructions to reset"
                                        + " your password."));
    }

    @PostMapping("/reset-password")
    @SecurityRequirements
    @Operation(
            summary = "Reset the password",
            description =
                    "Changes the password using the token from the recovery link. The token is"
                            + " single-use and expires.")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Password updated"),
        @ApiResponse(
                responseCode = "400",
                description = "Invalid data, or token invalid, expired or already used")
    })
    public ResponseEntity<Void> resetPassword(@Valid @RequestBody ResetPasswordResource resource) {
        passwordRecoveryUseCase.resetPassword(resource.token(), resource.newPassword());
        return ResponseEntity.noContent().build();
    }
}
