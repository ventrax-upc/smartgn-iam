package com.ventrax.iam.profile.interfaces.rest;

import com.ventrax.iam.auth.application.port.out.TokenClaims;
import com.ventrax.iam.auth.domain.model.Role;
import com.ventrax.iam.profile.application.port.in.CreateProfileCommand;
import com.ventrax.iam.profile.application.port.in.ManageProfileUseCase;
import com.ventrax.iam.profile.application.port.in.Requester;
import com.ventrax.iam.profile.application.port.in.UpdateProfileCommand;
import com.ventrax.iam.profile.domain.model.UserProfile;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/profiles")
@Tag(name = "Profiles", description = "Profile of the authenticated user")
public class ProfileController {

    private final ManageProfileUseCase profiles;

    public ProfileController(ManageProfileUseCase profiles) {
        this.profiles = profiles;
    }

    @PostMapping
    @Operation(
            summary = "Create my profile",
            description =
                    "Creates the profile of the authenticated account. Each account has a single"
                            + " profile.")
    @ApiResponses({
        @ApiResponse(responseCode = "201", description = "Profile created"),
        @ApiResponse(responseCode = "400", description = "Invalid data"),
        @ApiResponse(responseCode = "401", description = "Missing or invalid token"),
        @ApiResponse(responseCode = "409", description = "The account already has a profile")
    })
    public ResponseEntity<ProfileResource> create(
            @Parameter(hidden = true) @AuthenticationPrincipal TokenClaims me,
            @Valid @RequestBody CreateProfileResource resource) {
        UserProfile profile =
                profiles.create(
                        new CreateProfileCommand(
                                me.accountId(),
                                resource.firstName(),
                                resource.lastName(),
                                resource.phone(),
                                resource.address()));
        URI location =
                ServletUriComponentsBuilder.fromCurrentRequest()
                        .path("/{id}")
                        .buildAndExpand(profile.getId())
                        .toUri();
        return ResponseEntity.created(location).body(ProfileResource.from(profile));
    }

    @GetMapping("/me")
    @Operation(
            summary = "Get my profile",
            description = "Returns the profile of the authenticated account.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Profile found"),
        @ApiResponse(responseCode = "401", description = "Missing or invalid token"),
        @ApiResponse(responseCode = "404", description = "The account does not have a profile yet")
    })
    public ResponseEntity<ProfileResource> getMine(
            @Parameter(hidden = true) @AuthenticationPrincipal TokenClaims me) {
        return ResponseEntity.ok(ProfileResource.from(profiles.getMine(me.accountId())));
    }

    @GetMapping("/{profileId}")
    @Operation(
            summary = "Get a profile by id",
            description = "Only the profile owner or a SUPERADMIN can read it.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Profile found"),
        @ApiResponse(responseCode = "401", description = "Missing or invalid token"),
        @ApiResponse(responseCode = "403", description = "The profile belongs to another account"),
        @ApiResponse(responseCode = "404", description = "Profile not found")
    })
    public ResponseEntity<ProfileResource> getById(
            @Parameter(hidden = true) @AuthenticationPrincipal TokenClaims me,
            @PathVariable UUID profileId) {
        Requester requester = new Requester(me.accountId(), me.role() == Role.SUPERADMIN);
        return ResponseEntity.ok(ProfileResource.from(profiles.getById(profileId, requester)));
    }

    @PutMapping("/me")
    public ResponseEntity<ProfileResource> updateMine(
            @AuthenticationPrincipal TokenClaims me,
            @Valid @RequestBody UpdateProfileResource resource) {
        return update(me, profiles.getMine(me.accountId()).getId(), resource);
    }

    @PutMapping("/{profileId}")
    @Operation(
            summary = "Update my profile",
            description = "Replaces the profile data. Only the owner can modify it.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Profile updated"),
        @ApiResponse(responseCode = "400", description = "Invalid data"),
        @ApiResponse(responseCode = "401", description = "Missing or invalid token"),
        @ApiResponse(responseCode = "403", description = "The profile belongs to another account"),
        @ApiResponse(responseCode = "404", description = "Profile not found")
    })
    public ResponseEntity<ProfileResource> update(
            @Parameter(hidden = true) @AuthenticationPrincipal TokenClaims me,
            @PathVariable UUID profileId,
            @Valid @RequestBody UpdateProfileResource resource) {
        UserProfile profile =
                profiles.update(
                        new UpdateProfileCommand(
                                profileId,
                                me.accountId(),
                                resource.firstName(),
                                resource.lastName(),
                                resource.phone(),
                                resource.address()));
        return ResponseEntity.ok(ProfileResource.from(profile));
    }
}
