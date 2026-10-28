package com.smartgn.iam.auth.interfaces.rest;

import io.swagger.v3.oas.annotations.media.Schema;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ForgotPasswordResource(
        @Schema(example = "user@example.test") @NotBlank @Email @Size(max = 254) String email) {}
