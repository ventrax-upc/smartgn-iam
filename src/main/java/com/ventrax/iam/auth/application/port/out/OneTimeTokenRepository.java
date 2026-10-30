package com.ventrax.iam.auth.application.port.out;

import com.ventrax.iam.auth.domain.model.OneTimeToken;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface OneTimeTokenRepository {

    OneTimeToken save(OneTimeToken recoveryToken);

    /** Looks up by token hash and locks the row so it cannot be used twice in parallel. */
    Optional<OneTimeToken> findByTokenHash(String tokenHash);

    /** Marks every pending request of the account as used. */
    void invalidatePending(UUID accountId, Instant now);
}
