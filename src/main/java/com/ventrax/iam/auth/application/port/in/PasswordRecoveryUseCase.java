package com.ventrax.iam.auth.application.port.in;

public interface PasswordRecoveryUseCase {

    /**
     * Starts the recovery. Does not reveal whether the email is registered: never fails because of
     * an unknown email.
     */
    void requestRecovery(String email);

    /** Sets the new password if the token is valid, not expired and unused. */
    void resetPassword(String token, String newPassword);
}
