package com.ventrax.iam.auth.application.port.out;

/** Port to the external system that delivers the recovery link to the user. */
public interface PasswordResetNotifier {

    void send(PasswordResetNotification notification);
}
