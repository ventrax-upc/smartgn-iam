package com.ventrax.iam.profile.application.port.in;

import java.util.UUID;

/** Who makes the request, reduced to what the profile context needs to know. */
public record Requester(UUID accountId, boolean superAdmin) {}
