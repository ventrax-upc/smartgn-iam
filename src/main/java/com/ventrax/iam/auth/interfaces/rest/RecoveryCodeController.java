package com.ventrax.iam.auth.interfaces.rest;

import com.ventrax.iam.auth.application.service.PasswordRecoveryCodes;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@SecurityRequirements
@RequestMapping("/api/v1/auth/recovery-codes")
public class RecoveryCodeController {
    private final PasswordRecoveryCodes codes;

    public RecoveryCodeController(PasswordRecoveryCodes codes) {
        this.codes = codes;
    }

    public record Send(@NotBlank @Email @Size(max = 254) String email) {}
    public record Challenge(UUID challengeId) {}
    public record Verify(@NotNull UUID challengeId, @NotBlank @Pattern(regexp = "[0-9]{6}") String code) {}
    public record RecoveryProof(String token) {}

    @PostMapping
    @ResponseStatus(HttpStatus.ACCEPTED)
    @ApiResponse(responseCode = "400", description = "Email is invalid")
    @ApiResponse(responseCode = "404", description = "Email is not registered")
    @ApiResponse(responseCode = "409", description = "Account is inactive")
    @ApiResponse(responseCode = "429", description = "Recovery request limit exceeded")
    @ApiResponse(responseCode = "503", description = "Email delivery is unavailable")
    public Challenge send(@Valid @RequestBody Send request) {
        return new Challenge(codes.send(request.email()));
    }

    @PostMapping("/verify")
    @ApiResponse(responseCode = "400", description = "Challenge or code is invalid")
    @ApiResponse(responseCode = "422", description = "Code is incorrect or expired")
    public RecoveryProof verify(@Valid @RequestBody Verify request) {
        String token = codes.verify(request.challengeId(), request.code());
        if (token == null) throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "Invalid or expired code");
        return new RecoveryProof(token);
    }
}
