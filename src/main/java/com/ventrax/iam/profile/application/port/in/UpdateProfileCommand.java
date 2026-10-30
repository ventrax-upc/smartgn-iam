package com.ventrax.iam.profile.application.port.in;

import java.util.UUID;

public record UpdateProfileCommand(
        UUID profileId,
        UUID requesterAccountId,
        String firstName,
        String lastName,
        String phone,
        String address) {}
