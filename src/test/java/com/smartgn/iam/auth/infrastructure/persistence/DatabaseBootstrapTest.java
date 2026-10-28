package com.smartgn.iam.auth.infrastructure.persistence;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

@EnabledIfEnvironmentVariable(named = "SMARTGN_TEST_DATABASE_URL", matches = ".+")
class DatabaseBootstrapTest {
    @Test
    void freshSchemaSeparatesCredentialsAndContainsOnlyEnglishIdentityTables() throws Exception {
        String schema = "iam_bootstrap_" + UUID.randomUUID().toString().replace("-", "");
        JdbcTemplate db =
                new JdbcTemplate(
                        new DriverManagerDataSource(
                                System.getenv("SMARTGN_TEST_DATABASE_URL"),
                                System.getenv("SMARTGN_TEST_DATABASE_USERNAME"),
                                System.getenv("SMARTGN_TEST_DATABASE_PASSWORD")));
        db.execute("CREATE SCHEMA " + schema);
        try (var in = getClass().getResourceAsStream("/db/migration/V1__iam_schema.sql")) {
            assertNotNull(in);
            db.execute(
                    new String(in.readAllBytes(), StandardCharsets.UTF_8)
                            .replace("iam.", schema + "."));
            UUID account = UUID.randomUUID();
            db.update(
                    "INSERT INTO "
                            + schema
                            + ".user_accounts(account_id,email,role) VALUES (?,?,'USER')",
                    account,
                    account + "@example.test");
            db.update(
                    "INSERT INTO "
                            + schema
                            + ".password_credentials(credential_id,account_id,password_hash) VALUES"
                            + " (?,?,'test-hash')",
                    UUID.randomUUID(),
                    account);
            assertEquals(
                    "test-hash",
                    db.queryForObject(
                            "SELECT password_hash FROM "
                                    + schema
                                    + ".password_credentials WHERE account_id=?",
                            String.class,
                            account));
            assertEquals(
                    0,
                    db.queryForObject(
                            "SELECT count(*) FROM information_schema.columns WHERE table_schema=?"
                                + " AND table_name='user_accounts' AND column_name IN"
                                + " ('password_hash','plan')",
                            Integer.class,
                            schema));
            assertEquals(
                    3,
                    db.queryForObject(
                            "SELECT count(*) FROM information_schema.tables WHERE table_schema=?"
                                + " AND table_name IN"
                                + " ('delegations','meter_permission_grants','secure_deliveries')",
                            Integer.class,
                            schema));
            assertThrows(
                    org.springframework.dao.DataIntegrityViolationException.class,
                    () ->
                            db.update(
                                    "INSERT INTO "
                                            + schema
                                            + ".user_accounts(email,role) VALUES (?,'INSTALLER')",
                                    UUID.randomUUID() + "@example.test"));
        } finally {
            if (!schema.matches("iam_bootstrap_[a-f0-9]{32}"))
                throw new IllegalStateException("Unsafe test schema");
            db.execute("DROP SCHEMA " + schema + " CASCADE");
        }
    }
}
