package com.smartgn.iam.auth.interfaces.rest;

import io.swagger.v3.oas.annotations.media.Schema;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record SignInResource(
        @Schema(example = "user@example.test") @NotBlank @Size(max = 254) String email,
        @Schema(example = "Secret123") @NotBlank @Size(max = 72) String password) {}
