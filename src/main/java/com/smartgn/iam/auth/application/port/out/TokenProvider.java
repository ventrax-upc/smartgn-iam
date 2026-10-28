package com.smartgn.iam.auth.application.port.out;

import com.smartgn.iam.auth.domain.model.UserAccount;

import java.util.Optional;

public interface TokenProvider {

    String generateToken(UserAccount account);

    /** Returns the claims if the token is authentic and not expired; empty in any other case. */
    Optional<TokenClaims> validate(String token);
}
