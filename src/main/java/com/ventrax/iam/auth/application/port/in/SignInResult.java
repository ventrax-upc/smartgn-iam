package com.ventrax.iam.auth.application.port.in;

import com.ventrax.iam.auth.domain.model.UserAccount;

public record SignInResult(UserAccount account, String token) {}
