package com.ventrax.iam.auth.infrastructure.persistence;

import com.ventrax.iam.auth.application.port.in.IdentityOperations;
import com.ventrax.iam.auth.domain.model.IdentityPolicy;
import com.ventrax.iam.auth.infrastructure.notification.SecureDeliveryQueue;
import com.ventrax.iam.auth.infrastructure.security.Sha256ResetTokenCodec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestClient;
import org.springframework.web.server.ResponseStatusException;

import java.time.*;
import java.util.*;

@Service
public class JdbcIdentityOperations implements IdentityOperations {
    private final JdbcTemplate db;
    private final IdentityDenialAudit denialAudit;
    private final PasswordEncoder passwords;
    private final SecureDeliveryQueue delivery;
    private final Sha256ResetTokenCodec tokens;
    private final RestClient installation, billing;
    private final String serviceToken, billingToken;
    private final String activationLink;

    public JdbcIdentityOperations(
            JdbcTemplate db,
            IdentityDenialAudit denialAudit,
            PasswordEncoder passwords,
            SecureDeliveryQueue delivery,
            Sha256ResetTokenCodec tokens,
            @Value("${smartgn.installation.url:http://installation:8081}") String installationUrl,
            @Value("${smartgn.internal.token}") String serviceToken,
            @Value("${smartgn.billing.base-url:${smartgn.billing.fixture-url:}}") String billingUrl,
            @Value("${smartgn.billing.service-token:${smartgn.billing.fixture-token:}}")
                    String billingToken,
            @Value("${smartgn.activation.link:http://localhost:4200/activate-password}")
                    String activationLink) {
        this.db = db;
        this.denialAudit = denialAudit;
        this.passwords = passwords;
        this.delivery = delivery;
        this.tokens = tokens;
        this.serviceToken = serviceToken;
        this.billingToken = billingToken;
        this.activationLink = activationLink;
        var f =
                new org.springframework.http.client.JdkClientHttpRequestFactory(
                        java.net.http.HttpClient.newBuilder()
                                .connectTimeout(Duration.ofSeconds(2))
                                .build());
        f.setReadTimeout(Duration.ofSeconds(2));
        this.installation =
                RestClient.builder()
                        .baseUrl(installationUrl)
                        .requestFactory(f)
                        .requestInterceptor(
                                new com.ventrax.iam.shared.infrastructure.web.TraceHttpRequests())
                        .build();
        this.billing =
                RestClient.builder()
                        .baseUrl(billingUrl.isBlank() ? "http://127.0.0.1:1" : billingUrl)
                        .requestFactory(f)
                        .requestInterceptor(
                                new com.ventrax.iam.shared.infrastructure.web.TraceHttpRequests())
                        .build();
    }

    private static ResponseStatusException error(HttpStatus status, String message) {
        return new ResponseStatusException(status, message);
    }

    private static String email(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private static UUID correlation() {
        String value = org.slf4j.MDC.get("correlationId");
        return value == null ? UUID.randomUUID() : UUID.fromString(value);
    }

    private void event(String type, UUID id) {
        db.update(
                "INSERT INTO iam.domain_outbox(event_id,event_type,aggregate_id,correlation_id)"
                        + " VALUES (?,?,?,?)",
                UUID.randomUUID(),
                type,
                id,
                correlation());
    }

    private void audit(UUID actor, String action, UUID resource) {
        db.update(
                "INSERT INTO"
                        + " iam.identity_audit(audit_id,actor_id,action,resource_id,correlation_id)"
                        + " VALUES (?,?,?,?,?)",
                UUID.randomUUID(),
                actor,
                action,
                resource,
                correlation());
    }

    public Map<UUID, Set<String>> meterGrants(UUID account) {
        if (!"ACTIVE".equals(context(account).status()))
            throw error(HttpStatus.FORBIDDEN, "Account is inactive");
        Map<UUID, Set<String>> result = new TreeMap<>();
        for (var row :
                db.queryForList(
                        "SELECT g.meter_id,g.function FROM iam.meter_permission_grants g JOIN"
                            + " iam.delegations d USING(delegation_id) JOIN iam.user_accounts p ON"
                            + " p.account_id=d.principal_account_id WHERE d.delegate_account_id=?"
                            + " AND d.active AND p.account_status='ACTIVE' AND g.revoked_at IS"
                            + " NULL",
                        account))
            result.computeIfAbsent((UUID) row.get("meter_id"), k -> new TreeSet<>())
                    .add(row.get("function").toString());
        return result;
    }

    public Account context(UUID id) {
        return db
                .query(
                        "SELECT a.*,d.principal_account_id FROM iam.user_accounts a LEFT JOIN"
                                + " iam.delegations d ON d.delegate_account_id=a.account_id AND"
                                + " d.active WHERE account_id=?",
                        (s, n) ->
                                new Account(
                                        id,
                                        s.getString("email"),
                                        s.getString("role"),
                                        s.getString("account_kind"),
                                        s.getString("account_status"),
                                        s.getLong("session_version"),
                                        s.getObject("principal_account_id", UUID.class)),
                        id)
                .stream()
                .findFirst()
                .orElseThrow(() -> error(HttpStatus.NOT_FOUND, "Account not found"));
    }

    private void principal(UUID id) {
        Account a = context(id);
        if (!IdentityPolicy.principal(a.role(), a.accountKind(), a.status()))
            throw error(HttpStatus.FORBIDDEN, "An active principal USER account is required");
    }

    private UUID delegation(UUID principal, UUID subuser) {
        principal(principal);
        return db
                .query(
                        "SELECT * FROM iam.delegations WHERE principal_account_id=? AND"
                                + " delegate_account_id=? AND active FOR UPDATE",
                        (s, n) ->
                                new com.ventrax.iam.auth.domain.model.Delegation(
                                        s.getObject("delegation_id", UUID.class),
                                        s.getObject("principal_account_id", UUID.class),
                                        s.getObject("delegate_account_id", UUID.class),
                                        s.getBoolean("active")),
                        principal,
                        subuser)
                .stream()
                .filter(d -> d.belongsTo(principal))
                .map(com.ventrax.iam.auth.domain.model.Delegation::delegationId)
                .findFirst()
                .orElseThrow(
                        () ->
                                error(
                                        HttpStatus.FORBIDDEN,
                                        "Delegation is not owned by this principal"));
    }

    private void lock(String key) {
        db.queryForList("SELECT pg_advisory_xact_lock(hashtextextended(?,0))", key);
    }

    private Account pending(String email, String first, String last, String kind) {
        UUID id = UUID.randomUUID();
        db.update(
                "INSERT INTO iam.user_accounts(account_id,email,role,account_kind,account_status)"
                        + " VALUES (?,?,'USER',?,'PENDING_ACTIVATION')",
                id,
                email(email),
                kind);
        db.update(
                "INSERT INTO"
                    + " iam.user_profiles(profile_id,account_id,first_name,last_name,display_name)"
                    + " VALUES (?,?,?,?,?)",
                UUID.randomUUID(),
                id,
                first,
                last,
                first + " " + last);
        String plain = tokens.generateToken();
        db.update(
                "INSERT INTO iam.one_time_tokens(token_id,account_id,token_hash,purpose,expires_at)"
                        + " VALUES (?,?,?,'ACTIVATION',now()+interval '30 minutes')",
                UUID.randomUUID(),
                id,
                tokens.hash(plain));
        delivery.queue(
                Map.of(
                        "purpose",
                        "ACTIVATION",
                        "email",
                        email(email),
                        "token",
                        plain,
                        "link",
                        activationLink + "?token=" + plain));
        event("AccountProvisioned", id);
        return context(id);
    }

    @Transactional
    public Account provision(Purchase p) {
        if (!p.confirmed()) throw error(HttpStatus.CONFLICT, "A verified purchase is required");
        lock(p.purchaseOrderId().toString());
        var previous =
                db.queryForList(
                        "SELECT * FROM iam.purchase_receipts WHERE purchase_order_id=? OR"
                                + " event_id=?",
                        p.purchaseOrderId(),
                        p.eventId());
        if (!previous.isEmpty()) {
            var old = previous.getFirst();
            if (!p.purchaseOrderId().equals(old.get("purchase_order_id"))
                    || !email(p.email()).equals(old.get("email")))
                throw error(
                        HttpStatus.CONFLICT, "Purchase confirmation conflicts with its receipt");
            return context((UUID) old.get("account_id"));
        }
        Account a = pending(p.email(), p.firstName(), p.lastName(), "PRINCIPAL");
        db.update(
                "INSERT INTO iam.purchase_receipts(purchase_order_id,event_id,account_id,email)"
                        + " VALUES (?,?,?,?)",
                p.purchaseOrderId(),
                p.eventId(),
                a.accountId(),
                a.email());
        return a;
    }

    @Transactional
    public void activate(String token, String password) {
        var rows =
                db.queryForList(
                        "SELECT * FROM iam.one_time_tokens WHERE token_hash=? AND"
                            + " purpose='ACTIVATION' AND used_at IS NULL AND expires_at>now() FOR"
                            + " UPDATE",
                        tokens.hash(token));
        if (rows.isEmpty()) throw error(HttpStatus.BAD_REQUEST, "Invalid activation token");
        UUID id = (UUID) rows.getFirst().get("account_id");
        db.queryForList(
                "SELECT account_id FROM iam.user_accounts WHERE account_id=? FOR UPDATE", id);
        Account a = context(id);
        if (!"PENDING_ACTIVATION".equals(a.status()))
            throw error(HttpStatus.BAD_REQUEST, "Invalid activation token");
        boolean eligible =
                "DELEGATED".equals(a.accountKind())
                        ? a.principalAccountId() != null
                                && "ACTIVE".equals(context(a.principalAccountId()).status())
                        : Boolean.TRUE.equals(
                                db.queryForObject(
                                        "SELECT EXISTS(SELECT 1 FROM iam.purchase_receipts WHERE"
                                                + " account_id=?)",
                                        Boolean.class,
                                        id));
        if (!eligible)
            throw error(HttpStatus.CONFLICT, "Activation prerequisites are not confirmed");
        db.update(
                "INSERT INTO iam.password_credentials(credential_id,account_id,password_hash)"
                        + " VALUES (?,?,?)",
                UUID.randomUUID(),
                id,
                passwords.encode(password));
        db.update(
                "UPDATE iam.user_accounts SET account_status='ACTIVE',activated_at=now() WHERE"
                        + " account_id=?",
                id);
        db.update(
                "UPDATE iam.one_time_tokens SET used_at=now() WHERE account_id=? AND used_at IS"
                        + " NULL",
                id);
        event("AccountActivated", id);
    }

    @Transactional
    public void changePassword(UUID id, String current, String password) {
        db.queryForList(
                "SELECT account_id FROM iam.user_accounts WHERE account_id=? FOR UPDATE", id);
        if (!"ACTIVE".equals(context(id).status()))
            throw error(HttpStatus.UNAUTHORIZED, "Invalid account");
        String hash =
                db.queryForObject(
                        "SELECT password_hash FROM iam.password_credentials WHERE account_id=?",
                        String.class,
                        id);
        if (!passwords.matches(current, hash))
            throw error(HttpStatus.FORBIDDEN, "Current password is incorrect");
        db.update(
                "UPDATE iam.password_credentials SET password_hash=?,updated_at=now() WHERE"
                        + " account_id=?",
                passwords.encode(password),
                id);
        db.update(
                "UPDATE iam.user_accounts SET session_version=session_version+1 WHERE account_id=?",
                id);
        db.update(
                "UPDATE iam.one_time_tokens SET used_at=now() WHERE account_id=? AND used_at IS"
                        + " NULL",
                id);
        event("CredentialsChanged", id);
    }

    @Transactional
    public Account createSubuser(UUID principal, String email, String first, String last) {
        principal(principal);
        Account sub = pending(email, first, last, "DELEGATED");
        db.update(
                "INSERT INTO"
                        + " iam.delegations(delegation_id,principal_account_id,delegate_account_id)"
                        + " VALUES (?,?,?)",
                UUID.randomUUID(),
                principal,
                sub.accountId());
        audit(principal, "SUBUSER_CREATED", sub.accountId());
        return context(sub.accountId());
    }

    public List<Account> subusers(UUID principal) {
        principal(principal);
        return db.query(
                "SELECT delegate_account_id FROM iam.delegations WHERE principal_account_id=? ORDER"
                        + " BY created_at,delegation_id",
                (s, n) -> context(s.getObject(1, UUID.class)),
                principal);
    }

    @Transactional
    public Set<String> grants(UUID principal, UUID subuser, UUID meter) {
        UUID delegation = delegation(principal, subuser);
        return db
                .query(
                        "SELECT * FROM iam.meter_permission_grants WHERE delegation_id=? AND"
                                + " meter_id=?",
                        (row, index) ->
                                new com.ventrax.iam.auth.domain.model.MeterPermissionGrant(
                                        row.getObject("grant_id", UUID.class),
                                        row.getObject("meter_id", UUID.class),
                                        row.getString("function"),
                                        row.getTimestamp("granted_at").toInstant(),
                                        row.getTimestamp("revoked_at") == null
                                                ? null
                                                : row.getTimestamp("revoked_at").toInstant()),
                        delegation,
                        meter)
                .stream()
                .filter(com.ventrax.iam.auth.domain.model.MeterPermissionGrant::active)
                .map(com.ventrax.iam.auth.domain.model.MeterPermissionGrant::function)
                .collect(java.util.stream.Collectors.toCollection(TreeSet::new));
    }

    @Transactional
    public void grants(UUID principal, UUID subuser, UUID meter, Set<String> functions) {
        IdentityPolicy.functions(functions);
        UUID d = delegation(principal, subuser);
        if (!owns(principal, meter)) {
            denialAudit.record(principal, meter);
            throw error(HttpStatus.FORBIDDEN, "Meter belongs to another account");
        }
        Set<String> old = grants(principal, subuser, meter);
        for (String f : old)
            if (!functions.contains(f))
                db.update(
                        "UPDATE iam.meter_permission_grants SET revoked_at=now() WHERE"
                                + " delegation_id=? AND meter_id=? AND function=? AND revoked_at IS"
                                + " NULL",
                        d,
                        meter,
                        f);
        for (String f : functions)
            if (!old.contains(f))
                db.update(
                        "INSERT INTO"
                            + " iam.meter_permission_grants(grant_id,delegation_id,meter_id,function)"
                            + " VALUES (?,?,?,?)",
                        UUID.randomUUID(),
                        d,
                        meter,
                        f);
        event("MeterPermissionsChanged", subuser);
        audit(principal, "GRANTS_UPDATED", meter);
    }

    private boolean owns(UUID account, UUID meter) {
        try {
            var body =
                    installation
                            .get()
                            .uri("/internal/v1/meters/{id}/ownership", meter)
                            .header("Authorization", "Bearer " + serviceToken)
                            .retrieve()
                            .body(Map.class);
            return body != null
                    && account.toString().equals(body.get("ownerAccountId"))
                    && Boolean.TRUE.equals(body.get("active"));
        } catch (org.springframework.web.client.HttpClientErrorException.NotFound absent) {
            return false;
        } catch (Exception failure) {
            throw error(HttpStatus.SERVICE_UNAVAILABLE, "Meter ownership service unavailable");
        }
    }

    public boolean authorize(UUID account, UUID meter, String function, boolean requiresPro) {
        if (!IdentityPolicy.FUNCTIONS.contains(function)) return false;
        Account a = context(account);
        boolean allowed = "ACTIVE".equals(a.status());
        UUID principal = a.principalAccountId() == null ? account : a.principalAccountId();
        if (allowed) {
            if ("DELEGATED".equals(a.accountKind()))
                allowed =
                        a.principalAccountId() != null
                                && "ACTIVE".equals(context(principal).status())
                                && Boolean.TRUE.equals(
                                        db.queryForObject(
                                                "SELECT EXISTS(SELECT 1 FROM"
                                                    + " iam.meter_permission_grants g JOIN"
                                                    + " iam.delegations d USING(delegation_id)"
                                                    + " WHERE d.delegate_account_id=? AND d.active"
                                                    + " AND g.meter_id=? AND g.function=? AND"
                                                    + " g.revoked_at IS NULL)",
                                                Boolean.class,
                                                account,
                                                meter,
                                                function));
            if (allowed) allowed = owns(principal, meter);
        }
        if (allowed && requiresPro) {
            try {
                var body =
                        billing.get()
                                .uri("/internal/v1/accounts/{id}/entitlements", principal)
                                .header("Authorization", "Bearer " + billingToken)
                                .retrieve()
                                .body(Map.class);
                allowed = body != null && Boolean.TRUE.equals(body.get("proActive"));
            } catch (Exception failure) {
                throw error(HttpStatus.SERVICE_UNAVAILABLE, "Billing entitlement is not confirmed");
            }
        }
        if (!allowed) audit(account, "METER_ACCESS_DENIED", meter);
        return allowed;
    }
}
