package com.smartgn.iam.auth.application.port.in;

import java.util.*;

public interface IdentityOperations {
    record Account(
            UUID accountId,
            String email,
            String role,
            String accountKind,
            String status,
            long sessionVersion,
            UUID principalAccountId) {}

    record Purchase(
            UUID eventId,
            UUID purchaseOrderId,
            String email,
            String firstName,
            String lastName,
            boolean confirmed) {}

    Map<UUID, Set<String>> meterGrants(UUID account);

    Account provision(Purchase purchase);

    void activate(String token, String password);

    void changePassword(UUID account, String current, String password);

    Account context(UUID account);

    Account createSubuser(UUID principal, String email, String first, String last);

    List<Account> subusers(UUID principal);

    Set<String> grants(UUID principal, UUID subuser, UUID meter);

    void grants(UUID principal, UUID subuser, UUID meter, Set<String> functions);

    boolean authorize(UUID account, UUID meter, String function, boolean requiresPro);
}
