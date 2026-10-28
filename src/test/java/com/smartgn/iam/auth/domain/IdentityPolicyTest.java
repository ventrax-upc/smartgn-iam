package com.smartgn.iam.auth.domain;

import static org.junit.jupiter.api.Assertions.*;

import com.smartgn.iam.auth.domain.model.*;

import org.junit.jupiter.api.Test;

import java.util.*;

class IdentityPolicyTest {

    @Test
    void tokenPurposeAndConsumptionAreIndependentOfPasswordVerification() {
        var now = java.time.Instant.now();
        var activation =
                OneTimeToken.restore(
                        UUID.randomUUID(),
                        UUID.randomUUID(),
                        "hash",
                        now,
                        now.plusSeconds(60),
                        null,
                        OneTimeToken.Purpose.ACTIVATION);
        assertTrue(activation.canConsume(OneTimeToken.Purpose.ACTIVATION, now));
        assertFalse(activation.canConsume(OneTimeToken.Purpose.RECOVERY, now));
        activation.markUsed(now);
        assertFalse(activation.canConsume(OneTimeToken.Purpose.ACTIVATION, now));
    }

    @Test
    void onlyTheSixDocumentedFunctionsAreDelegable() {
        IdentityPolicy.functions(Set.of("USE_TICKETS", "USE_VISITS"));
        for (String f :
                List.of("PAYMENTS", "CARDS", "SUBSCRIPTIONS", "MANAGE_SUBUSERS", "SUPERADMIN"))
            assertThrows(IllegalArgumentException.class, () -> IdentityPolicy.functions(Set.of(f)));
        assertEquals(6, IdentityPolicy.FUNCTIONS.size());
    }

    @Test
    void sameUserRoleDoesNotMakeADelegateAPrincipal() {
        assertTrue(IdentityPolicy.principal("USER", "PRINCIPAL", "ACTIVE"));
        assertFalse(IdentityPolicy.principal("USER", "DELEGATED", "ACTIVE"));
        assertFalse(IdentityPolicy.principal("USER", "PRINCIPAL", "PENDING_ACTIVATION"));
        assertFalse(IdentityPolicy.principal("SUPERADMIN", "PRINCIPAL", "ACTIVE"));
    }

    @Test
    void domainModelsHaveNoPersistenceAnnotations() {
        for (Class<?> c :
                List.of(
                        UserAccount.class,
                        OneTimeToken.class,
                        com.smartgn.iam.profile.domain.model.UserProfile.class)) {
            assertEquals(0, c.getAnnotations().length);
            for (var field : c.getDeclaredFields()) assertEquals(0, field.getAnnotations().length);
        }
    }
}
