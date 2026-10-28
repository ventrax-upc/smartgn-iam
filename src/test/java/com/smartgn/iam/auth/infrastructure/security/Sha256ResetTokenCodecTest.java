package com.smartgn.iam.auth.infrastructure.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class Sha256ResetTokenCodecTest {

    private final Sha256ResetTokenCodec codec = new Sha256ResetTokenCodec();

    @Test
    void generatesDistinctSecureTokens() {
        String a = codec.generateToken();
        String b = codec.generateToken();

        assertNotEquals(a, b);
        assertTrue(a.length() >= 43);
        assertTrue(a.matches("[A-Za-z0-9_-]+"));
    }

    @Test
    void hashIsDeterministicAndHas64HexCharacters() {
        String hash = codec.hash("TOKEN");

        assertEquals(hash, codec.hash("TOKEN"));
        assertEquals(64, hash.length());
        assertNotEquals(hash, codec.hash("OTRO"));
    }
}
