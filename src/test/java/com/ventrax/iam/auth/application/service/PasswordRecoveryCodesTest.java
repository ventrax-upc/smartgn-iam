package com.ventrax.iam.auth.application.service;

import com.ventrax.iam.auth.application.port.out.AccountRepository;
import com.ventrax.iam.auth.application.port.out.OneTimeTokenRepository;
import com.ventrax.iam.auth.application.port.out.ResetTokenCodec;
import com.ventrax.iam.auth.domain.model.UserAccount;
import com.ventrax.iam.auth.infrastructure.notification.SecureDeliveryQueue;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Clock;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class PasswordRecoveryCodesTest {
    @Test
    void returnsOpaqueChallengesWithoutSendingMailForIneligibleAccounts() {
        var db = mock(JdbcTemplate.class);
        var accounts = mock(AccountRepository.class);
        var delivery = mock(SecureDeliveryQueue.class);
        var tokens = mock(OneTimeTokenRepository.class);
        var inactive = mock(UserAccount.class);
        when(delivery.isConfigured()).thenReturn(true);
        when(accounts.findByEmail("inactive@example.test")).thenReturn(Optional.of(inactive));
        when(accounts.findByEmail("unknown@example.test")).thenReturn(Optional.empty());
        var service = new PasswordRecoveryCodes(db, accounts, tokens, mock(ResetTokenCodec.class),
                delivery, Clock.systemUTC(), "test-only-key");

        var unknownChallenge = service.send(" Unknown@Example.Test ");
        var inactiveChallenge = service.send("inactive@example.test");

        assertNotNull(unknownChallenge);
        assertNotNull(inactiveChallenge);
        assertNotEquals(unknownChallenge, inactiveChallenge);
        verifyNoInteractions(db, tokens);
        org.mockito.Mockito.verify(delivery, org.mockito.Mockito.never()).queue(org.mockito.ArgumentMatchers.anyMap());
    }
}
