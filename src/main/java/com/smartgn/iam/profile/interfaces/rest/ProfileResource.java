package com.smartgn.iam.profile.interfaces.rest;

import com.smartgn.iam.profile.domain.model.UserProfile;

import java.util.UUID;

public record ProfileResource(
        UUID id, UUID accountId, String firstName, String lastName, String phone, String address) {

    public static ProfileResource from(UserProfile profile) {
        return new ProfileResource(
                profile.getId(),
                profile.getAccountId(),
                profile.getFirstName(),
                profile.getLastName(),
                profile.getPhone(),
                profile.getAddress());
    }
}
