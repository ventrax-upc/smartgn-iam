package com.smartgn.iam.auth.application.port.out;

import java.time.Instant;

public record PasswordResetNotification(
        String email, String token, String link, Instant expiresAt) {}
