package com.smartgn.iam.profile.domain.exception;

public class ProfileAccessDeniedException extends RuntimeException {

    public ProfileAccessDeniedException() {
        super("You do not have permission to access this profile");
    }
}
