package com.smartgn.iam.auth.application.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.smartgn.iam.auth.application.port.out.AccountRepository;
import com.smartgn.iam.auth.application.port.out.OneTimeTokenRepository;
import com.smartgn.iam.auth.application.port.out.PasswordResetNotification;
import com.smartgn.iam.auth.application.port.out.PasswordResetNotifier;
import com.smartgn.iam.auth.application.port.out.ResetTokenCodec;
import com.smartgn.iam.auth.domain.exception.InvalidRecoveryTokenException;
import com.smartgn.iam.auth.domain.model.OneTimeToken;
import com.smartgn.iam.auth.domain.model.Role;
import com.smartgn.iam.auth.domain.model.UserAccount;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

@ExtendWith(MockitoExtension.class)
class PasswordRecoveryServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-04T10:00:00Z");

    @Mock AccountRepository accounts;
    @Mock OneTimeTokenRepository recoveryTokens;
    @Mock ResetTokenCodec codec;
    @Mock PasswordResetNotifier notifier;
    @Mock PasswordEncoder passwordEncoder;

    private PasswordRecoveryService service;
    private final UUID accountId = UUID.randomUUID();
    private UserAccount account;

    @BeforeEach
    void setUp() {
        service =
                new PasswordRecoveryService(
                        accounts,
                        recoveryTokens,
                        codec,
                        notifier,
                        passwordEncoder,
                        Clock.fixed(NOW, ZoneOffset.UTC),
                        "http://front/reset",
                        30);
        account = UserAccount.create("user@example.test", "OLDHASH", Role.USER);
        ReflectionTestUtils.setField(account, "id", accountId);
    }

    @Test
    void recoveryStoresOnlyHashAndQueuesLink() {
        when(accounts.findByEmail("user@example.test")).thenReturn(Optional.of(account));
        when(codec.generateToken()).thenReturn("TOKEN");
        when(codec.hash("TOKEN")).thenReturn("HASH");

        service.requestRecovery(" User@Example.test ");

        ArgumentCaptor<OneTimeToken> savedToken = ArgumentCaptor.forClass(OneTimeToken.class);
        verify(recoveryTokens).invalidatePending(accountId, NOW);
        verify(recoveryTokens).save(savedToken.capture());
        assertEquals("HASH", savedToken.getValue().getTokenHash());
        assertEquals(NOW.plus(Duration.ofMinutes(30)), savedToken.getValue().getExpiresAt());

        ArgumentCaptor<PasswordResetNotification> notification =
                ArgumentCaptor.forClass(PasswordResetNotification.class);
        verify(notifier).send(notification.capture());
        assertEquals("user@example.test", notification.getValue().email());
        assertEquals("http://front/reset?token=TOKEN", notification.getValue().link());
    }

    @Test
    void unknownEmailDoesNotFailOrQueueRecovery() {
        when(accounts.findByEmail("unknown@example.test")).thenReturn(Optional.empty());

        assertDoesNotThrow(() -> service.requestRecovery("unknown@example.test"));
        verifyNoInteractions(recoveryTokens, notifier, codec);
    }

    @Test
    void recoveryResponseIsUniformWhenDeliveryFails() {
        when(accounts.findByEmail("user@example.test")).thenReturn(Optional.of(account));
        when(codec.generateToken()).thenReturn("TOKEN");
        when(codec.hash("TOKEN")).thenReturn("HASH");
        doThrow(new RuntimeException("delivery unavailable")).when(notifier).send(any());

        assertDoesNotThrow(() -> service.requestRecovery("user@example.test"));
    }

    @Test
    void resetChangesPasswordAndConsumesToken() {
        OneTimeToken pendingToken =
                OneTimeToken.create(accountId, "HASH", NOW.minusSeconds(60), NOW.plusSeconds(600));
        when(codec.hash("TOKEN")).thenReturn("HASH");
        when(recoveryTokens.findByTokenHash("HASH")).thenReturn(Optional.of(pendingToken));
        when(accounts.findById(accountId)).thenReturn(Optional.of(account));
        when(passwordEncoder.encode("NewPassword123")).thenReturn("NEWHASH");

        service.resetPassword("TOKEN", "NewPassword123");

        assertEquals("NEWHASH", account.getPasswordHash());
        assertFalse(pendingToken.isValid(NOW));
        verify(accounts).save(account);
        verify(recoveryTokens).invalidatePending(accountId, NOW);
    }

    @Test
    void resetRejectsUnknownToken() {
        when(codec.hash("TOKEN")).thenReturn("HASH");
        when(recoveryTokens.findByTokenHash("HASH")).thenReturn(Optional.empty());

        assertThrows(
                InvalidRecoveryTokenException.class,
                () -> service.resetPassword("TOKEN", "NewPassword123"));
        verifyNoInteractions(passwordEncoder);
    }

    @Test
    void resetRejectsExpiredToken() {
        OneTimeToken expiredToken =
                OneTimeToken.create(accountId, "HASH", NOW.minusSeconds(3600), NOW.minusSeconds(1));
        when(codec.hash("TOKEN")).thenReturn("HASH");
        when(recoveryTokens.findByTokenHash("HASH")).thenReturn(Optional.of(expiredToken));

        assertThrows(
                InvalidRecoveryTokenException.class,
                () -> service.resetPassword("TOKEN", "NewPassword123"));
        verify(accounts, never()).save(any());
    }

    @Test
    void resetRejectsUsedToken() {
        OneTimeToken usedToken =
                OneTimeToken.create(accountId, "HASH", NOW.minusSeconds(60), NOW.plusSeconds(600));
        usedToken.markUsed(NOW.minusSeconds(10));
        when(codec.hash("TOKEN")).thenReturn("HASH");
        when(recoveryTokens.findByTokenHash("HASH")).thenReturn(Optional.of(usedToken));

        assertThrows(
                InvalidRecoveryTokenException.class,
                () -> service.resetPassword("TOKEN", "NewPassword123"));
        verify(accounts, never()).save(any());
    }
}
