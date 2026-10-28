package com.smartgn.iam.profile.interfaces.rest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.validation.Validation;
import jakarta.validation.Validator;

import org.junit.jupiter.api.Test;

class ProfileResourceValidationTest {

    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    void acceptsValidDataWithEmptyOptionalFields() {
        assertTrue(
                validator
                        .validate(new CreateProfileResource("Ana", "Perez", null, null))
                        .isEmpty());
        assertTrue(
                validator
                        .validate(
                                new CreateProfileResource(
                                        "Ana", "Perez", "+51 987 654 321", "Av. Lima 1"))
                        .isEmpty());
    }

    @Test
    void rejectsBlankFirstOrLastName() {
        assertEquals(
                1, validator.validate(new CreateProfileResource("  ", "Perez", null, null)).size());
        assertEquals(
                1, validator.validate(new UpdateProfileResource("Ana", "", null, null)).size());
    }

    @Test
    void rejectsInvalidPhoneFormat() {
        assertEquals(
                1,
                validator
                        .validate(new CreateProfileResource("Ana", "Perez", "abc123", null))
                        .size());
        assertEquals(
                1,
                validator.validate(new UpdateProfileResource("Ana", "Perez", "12", null)).size());
    }

    @Test
    void rejectsAddressExceedingMaximumLength() {
        String longAddress = "x".repeat(256);
        assertEquals(
                1,
                validator
                        .validate(new CreateProfileResource("Ana", "Perez", null, longAddress))
                        .size());
    }
}
