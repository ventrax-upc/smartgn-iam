package com.smartgn.iam.auth.application.port.in;

public record SignInCommand(String email, String password) {}
