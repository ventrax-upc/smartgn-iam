package com.ventrax.iam.auth.application.port.in;

public interface SignInUseCase {

    SignInResult execute(SignInCommand command);
}
