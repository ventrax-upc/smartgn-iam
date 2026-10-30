package com.ventrax.iam.profile.domain.exception;

public class ProfileNotFoundException extends RuntimeException {

    public ProfileNotFoundException() {
        super("Profile not found");
    }
}
