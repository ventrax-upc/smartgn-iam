package com.ventrax.iam.profile.application.port.in;

import java.util.UUID;

public record CreateProfileCommand(
        UUID accountId, String firstName, String lastName, String phone, String address) {}
