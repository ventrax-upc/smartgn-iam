package com.ventrax.iam.auth.application.port.out;

import com.ventrax.iam.auth.domain.model.UserAccount;

import java.util.Optional;
import java.util.UUID;

public interface AccountRepository {

    boolean existsByEmail(String email);

    Optional<UserAccount> findById(UUID id);

    Optional<UserAccount> findByEmail(String email);

    UserAccount save(UserAccount account);
}
