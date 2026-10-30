package com.ventrax.iam.auth.application.service;

import com.ventrax.iam.auth.application.port.in.SignInCommand;
import com.ventrax.iam.auth.application.port.in.SignInResult;
import com.ventrax.iam.auth.application.port.in.SignInUseCase;
import com.ventrax.iam.auth.application.port.out.AccountRepository;
import com.ventrax.iam.auth.application.port.out.TokenProvider;
import com.ventrax.iam.auth.domain.exception.InvalidCredentialsException;
import com.ventrax.iam.auth.domain.model.UserAccount;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import java.util.Optional;

@Service
public class SignInService implements SignInUseCase {

    private final AccountRepository accounts;
    private final PasswordEncoder passwordEncoder;
    private final TokenProvider tokenProvider;
    // Dummy hash so the response time is similar whether or not the email exists
    private final String dummyPasswordHash;

    public SignInService(
            AccountRepository accounts,
            PasswordEncoder passwordEncoder,
            TokenProvider tokenProvider) {
        this.accounts = accounts;
        this.passwordEncoder = passwordEncoder;
        this.tokenProvider = tokenProvider;
        this.dummyPasswordHash = passwordEncoder.encode("dummy-password");
    }

    @Override
    @Transactional(readOnly = true)
    public SignInResult execute(SignInCommand command) {
        String email = command.email().trim().toLowerCase(Locale.ROOT);
        Optional<UserAccount> foundAccount = accounts.findByEmail(email);

        if (foundAccount.isEmpty()) {
            passwordEncoder.matches(command.password(), dummyPasswordHash);
            throw new InvalidCredentialsException();
        }

        UserAccount account = foundAccount.get();
        if (!"ACTIVE".equals(account.getStatus())
                || account.getPasswordHash() == null
                || !passwordEncoder.matches(command.password(), account.getPasswordHash())) {
            throw new InvalidCredentialsException();
        }

        return new SignInResult(account, tokenProvider.generateToken(account));
    }
}
