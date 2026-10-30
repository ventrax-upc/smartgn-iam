package com.ventrax.iam.auth.domain.exception;

public class InvalidRecoveryTokenException extends RuntimeException {

    public InvalidRecoveryTokenException() {
        super("The recovery link is invalid or has expired");
    }
}
