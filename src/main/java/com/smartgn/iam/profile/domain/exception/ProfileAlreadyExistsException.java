package com.smartgn.iam.profile.domain.exception;

public class ProfileAlreadyExistsException extends RuntimeException {

    public ProfileAlreadyExistsException() {
        super("The account already has a registered profile");
    }
}
