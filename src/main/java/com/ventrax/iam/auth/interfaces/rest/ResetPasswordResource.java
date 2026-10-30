package com.ventrax.iam.auth.interfaces.rest;

import io.swagger.v3.oas.annotations.media.Schema;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ResetPasswordResource(
        @Schema(description = "Token received in the recovery link") @NotBlank @Size(max = 200)
                String token,
        @Schema(example = "NewPassword123", description = "Between 8 and 72 characters")
                @NotBlank
                @Size(min = 8, max = 72)
                String newPassword) {}
