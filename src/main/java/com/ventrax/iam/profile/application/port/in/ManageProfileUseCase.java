package com.ventrax.iam.profile.application.port.in;

import com.ventrax.iam.profile.domain.model.UserProfile;

import java.util.UUID;

public interface ManageProfileUseCase {

    UserProfile create(CreateProfileCommand command);

    UserProfile getById(UUID profileId, Requester requester);

    UserProfile getMine(UUID accountId);

    UserProfile update(UpdateProfileCommand command);
}
