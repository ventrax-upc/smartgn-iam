package com.ventrax.iam.auth.application.port.out;

public interface ResetTokenCodec {

    /** Random, unpredictable token that is safe to use in a URL. */
    String generateToken();

    /** Deterministic hash used to store and look up the token. */
    String hash(String token);
}
