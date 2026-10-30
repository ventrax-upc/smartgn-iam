package com.ventrax.iam.auth.infrastructure.security;

import com.ventrax.iam.auth.application.port.out.ResetTokenCodec;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

@Component
public class Sha256ResetTokenCodec implements ResetTokenCodec {

    private final SecureRandom random = new SecureRandom();

    @Override
    public String generateToken() {
        byte[] bytes = new byte[32]; // 256 bits of entropy
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    @Override
    public String hash(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
