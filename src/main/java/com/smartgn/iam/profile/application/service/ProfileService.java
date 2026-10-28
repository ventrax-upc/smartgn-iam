package com.smartgn.iam.profile.application.service;

import com.smartgn.iam.profile.application.port.in.CreateProfileCommand;
import com.smartgn.iam.profile.application.port.in.ManageProfileUseCase;
import com.smartgn.iam.profile.application.port.in.Requester;
import com.smartgn.iam.profile.application.port.in.UpdateProfileCommand;
import com.smartgn.iam.profile.application.port.out.ProfileRepository;
import com.smartgn.iam.profile.domain.exception.ProfileAccessDeniedException;
import com.smartgn.iam.profile.domain.exception.ProfileAlreadyExistsException;
import com.smartgn.iam.profile.domain.exception.ProfileNotFoundException;
import com.smartgn.iam.profile.domain.model.UserProfile;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
public class ProfileService implements ManageProfileUseCase {

    private final ProfileRepository profiles;

    public ProfileService(ProfileRepository profiles) {
        this.profiles = profiles;
    }

    @Override
    @Transactional
    public UserProfile create(CreateProfileCommand command) {
        if (profiles.existsByAccountId(command.accountId())) {
            throw new ProfileAlreadyExistsException();
        }
        UserProfile profile =
                UserProfile.create(
                        command.accountId(),
                        command.firstName(),
                        command.lastName(),
                        command.phone(),
                        command.address());
        return profiles.save(profile);
    }

    @Override
    @Transactional(readOnly = true)
    public UserProfile getById(UUID profileId, Requester requester) {
        UserProfile profile =
                profiles.findById(profileId).orElseThrow(ProfileNotFoundException::new);
        if (!profile.belongsTo(requester.accountId()) && !requester.superAdmin()) {
            throw new ProfileAccessDeniedException();
        }
        return profile;
    }

    @Override
    @Transactional(readOnly = true)
    public UserProfile getMine(UUID accountId) {
        return profiles.findByAccountId(accountId).orElseThrow(ProfileNotFoundException::new);
    }

    @Override
    @Transactional
    public UserProfile update(UpdateProfileCommand command) {
        UserProfile profile =
                profiles.findById(command.profileId()).orElseThrow(ProfileNotFoundException::new);
        if (!profile.belongsTo(command.requesterAccountId())) {
            throw new ProfileAccessDeniedException();
        }
        profile.update(command.firstName(), command.lastName(), command.phone(), command.address());
        return profiles.save(profile);
    }
}
