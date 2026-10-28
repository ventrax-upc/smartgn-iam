package com.smartgn.iam.auth.application.port.in;

import com.smartgn.iam.auth.domain.model.UserAccount;

public record SignInResult(UserAccount account, String token) {}
