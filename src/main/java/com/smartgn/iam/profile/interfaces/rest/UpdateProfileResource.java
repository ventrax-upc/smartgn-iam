package com.smartgn.iam.profile.interfaces.rest;

import io.swagger.v3.oas.annotations.media.Schema;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

@Schema(
        description =
                "Full replacement of the profile: if phone or address are not sent, they are"
                        + " cleared.")
public record UpdateProfileResource(
        @Schema(example = "Ana") @NotBlank @Size(max = 100) String firstName,
        @Schema(example = "Perez") @NotBlank @Size(max = 100) String lastName,
        @Schema(example = "987654321")
                @Pattern(
                        regexp = "^\\+?[0-9 ()-]{7,20}$",
                        message = "The phone number has an invalid format")
                String phone,
        @Schema(example = "1234 Arequipa Avenue, Lima") @Size(max = 255) String address) {}
