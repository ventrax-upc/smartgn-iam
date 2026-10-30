package com.ventrax.iam.auth.application.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.ventrax.iam.auth.application.port.in.SignInCommand;
import com.ventrax.iam.auth.application.port.in.SignInResult;
import com.ventrax.iam.auth.application.port.out.AccountRepository;
import com.ventrax.iam.auth.application.port.out.TokenProvider;
import com.ventrax.iam.auth.domain.exception.InvalidCredentialsException;
import com.ventrax.iam.auth.domain.model.Role;
import com.ventrax.iam.auth.domain.model.UserAccount;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

@ExtendWith(MockitoExtension.class)
class SignInServiceTest {

    @Mock AccountRepository accounts;
    @Mock PasswordEncoder passwordEncoder;
    @Mock TokenProvider tokenProvider;
    @InjectMocks SignInService service;

    private final UserAccount account = UserAccount.create("user@example.test", "HASH", Role.USER);

    @Test
    void returnsTokenForValidCredentials() {
        when(accounts.findByEmail("user@example.test")).thenReturn(Optional.of(account));
        when(passwordEncoder.matches("Secret123", "HASH")).thenReturn(true);
        when(tokenProvider.generateToken(account)).thenReturn("JWT");

        SignInResult result =
                service.execute(new SignInCommand(" User@Example.test ", "Secret123"));

        assertEquals("JWT", result.token());
        assertEquals("user@example.test", result.account().getEmail());
    }

    @Test
    void rejectsIncorrectPassword() {
        when(accounts.findByEmail("user@example.test")).thenReturn(Optional.of(account));
        when(passwordEncoder.matches("wrong", "HASH")).thenReturn(false);

        assertThrows(
                InvalidCredentialsException.class,
                () -> service.execute(new SignInCommand("user@example.test", "wrong")));
        verifyNoInteractions(tokenProvider);
    }

    @Test
    void rejectsUnknownEmail() {
        when(accounts.findByEmail("unknown@example.test")).thenReturn(Optional.empty());

        assertThrows(
                InvalidCredentialsException.class,
                () -> service.execute(new SignInCommand("unknown@example.test", "Secret123")));
        verifyNoInteractions(tokenProvider);
    }
}
