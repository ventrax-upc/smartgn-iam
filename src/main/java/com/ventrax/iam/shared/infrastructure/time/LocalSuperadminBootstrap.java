package com.ventrax.iam.shared.infrastructure.time;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.*;

@Configuration
@Profile("local-bootstrap")
public class LocalSuperadminBootstrap {
    @Bean
    ApplicationRunner bootstrap(
            JdbcTemplate db,
            TransactionTemplate tx,
            PasswordEncoder encoder,
            @Value("${BOOTSTRAP_SUPERADMIN_EMAIL}") String email,
            @Value("${BOOTSTRAP_SUPERADMIN_PASSWORD}") String password) {
        return args -> {
            if (password.length() < 16)
                throw new IllegalArgumentException(
                        "Local bootstrap password must contain at least 16 characters");
            tx.executeWithoutResult(
                    status -> {
                        var existing =
                                db.queryForList(
                                        "SELECT role FROM iam.user_accounts WHERE email=?",
                                        email.toLowerCase(Locale.ROOT));
                        if (!existing.isEmpty()) {
                            if (!"SUPERADMIN".equals(existing.getFirst().get("role")))
                                throw new IllegalStateException(
                                        "Bootstrap email is already in use");
                            return;
                        }
                        UUID id = UUID.randomUUID();
                        db.update(
                                "INSERT INTO"
                                    + " iam.user_accounts(account_id,email,role,account_kind,account_status,activated_at)"
                                    + " VALUES (?,?,'SUPERADMIN','PRINCIPAL','ACTIVE',now())",
                                id,
                                email.toLowerCase(Locale.ROOT));
                        db.update(
                                "INSERT INTO"
                                    + " iam.password_credentials(credential_id,account_id,password_hash)"
                                    + " VALUES (?,?,?)",
                                UUID.randomUUID(),
                                id,
                                encoder.encode(password));
                    });
        };
    }
}
