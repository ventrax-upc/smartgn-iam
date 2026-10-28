package com.smartgn.iam.auth.domain.exception;

public class EmailAlreadyRegisteredException extends RuntimeException {

    public EmailAlreadyRegisteredException(String email) {
        super("The email is already associated with an existing account: " + email);
    }
}
