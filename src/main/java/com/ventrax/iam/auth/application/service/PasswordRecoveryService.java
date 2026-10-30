package com.ventrax.iam.auth.application.service;

import com.ventrax.iam.auth.application.port.in.PasswordRecoveryUseCase;
import com.ventrax.iam.auth.application.port.out.AccountRepository;
import com.ventrax.iam.auth.application.port.out.OneTimeTokenRepository;
import com.ventrax.iam.auth.application.port.out.PasswordResetNotification;
import com.ventrax.iam.auth.application.port.out.PasswordResetNotifier;
import com.ventrax.iam.auth.application.port.out.ResetTokenCodec;
import com.ventrax.iam.auth.domain.exception.InvalidRecoveryTokenException;
import com.ventrax.iam.auth.domain.model.OneTimeToken;
import com.ventrax.iam.auth.domain.model.UserAccount;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;

@Service
public class PasswordRecoveryService implements PasswordRecoveryUseCase {

    private static final Logger log = LoggerFactory.getLogger(PasswordRecoveryService.class);

    private final AccountRepository accounts;
    private final OneTimeTokenRepository recoveryTokens;
    private final ResetTokenCodec codec;
    private final PasswordResetNotifier notifier;
    private final PasswordEncoder passwordEncoder;
    private final Clock clock;
    private final String linkBaseUrl;
    private final Duration validity;

    public PasswordRecoveryService(
            AccountRepository accounts,
            OneTimeTokenRepository recoveryTokens,
            ResetTokenCodec codec,
            PasswordResetNotifier notifier,
            PasswordEncoder passwordEncoder,
            Clock clock,
            @Value("${smartgn.password-reset.link-base-url}") String linkBaseUrl,
            @Value("${smartgn.password-reset.expiration-minutes}") long expirationMinutes) {
        this.accounts = accounts;
        this.recoveryTokens = recoveryTokens;
        this.codec = codec;
        this.notifier = notifier;
        this.passwordEncoder = passwordEncoder;
        this.clock = clock;
        this.linkBaseUrl = linkBaseUrl;
        this.validity = Duration.ofMinutes(expirationMinutes);
    }

    // Token and encrypted delivery request commit atomically.
    @Override
    @Transactional
    public void requestRecovery(String rawEmail) {
        String email = rawEmail.trim().toLowerCase(Locale.ROOT);
        Optional<UserAccount> foundAccount = accounts.findByEmail(email);
        if (foundAccount.isEmpty() || !"ACTIVE".equals(foundAccount.get().getStatus())) {
            return;
        }
        UserAccount account = foundAccount.get();

        Instant now = clock.instant();
        Instant expiresAt = now.plus(validity);

        recoveryTokens.invalidatePending(account.getId(), now);
        String token = codec.generateToken();
        recoveryTokens.save(
                OneTimeToken.create(account.getId(), codec.hash(token), now, expiresAt));

        String link = linkBaseUrl + "?token=" + token;
        try {
            notifier.send(new PasswordResetNotification(email, token, link, expiresAt));
        } catch (RuntimeException e) {
            // The client response must not change if the external system fails
            log.warn(
                    "Could not queue password recovery for account {}: {}",
                    account.getId(),
                    e.getClass().getSimpleName());
        }
    }

    @Override
    @Transactional
    public void resetPassword(String token, String newPassword) {
        OneTimeToken recoveryToken =
                recoveryTokens
                        .findByTokenHash(codec.hash(token))
                        .orElseThrow(InvalidRecoveryTokenException::new);

        Instant now = clock.instant();
        if (!recoveryToken.canConsume(OneTimeToken.Purpose.RECOVERY, now)) {
            throw new InvalidRecoveryTokenException();
        }

        UserAccount account =
                accounts.findById(recoveryToken.getAccountId())
                        .orElseThrow(InvalidRecoveryTokenException::new);

        if (!"ACTIVE".equals(account.getStatus())) throw new InvalidRecoveryTokenException();
        account.changePasswordHash(passwordEncoder.encode(newPassword));
        accounts.save(account);

        recoveryToken.markUsed(now);
        recoveryTokens.save(recoveryToken);
        recoveryTokens.invalidatePending(account.getId(), now);
    }
}
