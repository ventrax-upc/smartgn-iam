package com.ventrax.iam.profile.application.port.out;

import com.ventrax.iam.profile.domain.model.UserProfile;

import java.util.Optional;
import java.util.UUID;

public interface ProfileRepository {

    boolean existsByAccountId(UUID accountId);

    Optional<UserProfile> findById(UUID id);

    Optional<UserProfile> findByAccountId(UUID accountId);

    UserProfile save(UserProfile profile);
}
