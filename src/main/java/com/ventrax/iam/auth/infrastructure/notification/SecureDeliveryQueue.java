package com.ventrax.iam.auth.infrastructure.notification;

import com.ventrax.iam.auth.application.port.out.*;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import tools.jackson.databind.ObjectMapper;

import java.security.*;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.*;

@Component
public class SecureDeliveryQueue implements PasswordResetNotifier {
    private final JdbcTemplate db;
    private final ObjectMapper json;
    private final byte[] key;
    private final String url, token;
    private final RestClient http;

    public SecureDeliveryQueue(
            JdbcTemplate db,
            ObjectMapper json,
            @Value("${smartgn.delivery.key}") String key,
            @Value("${smartgn.delivery.url:}") String url,
            @Value("${smartgn.delivery.token:}") String token) {
        this.db = db;
        this.json = json;
        this.key = Base64.getDecoder().decode(key);
        if (this.key.length != 32)
            throw new IllegalArgumentException("Delivery encryption requires 32 bytes");
        this.url = url;
        this.token = token;
        this.http =
                RestClient.builder()
                        .requestFactory(
                                new org.springframework.http.client.JdkClientHttpRequestFactory(
                                        java.net.http.HttpClient.newBuilder()
                                                .connectTimeout(java.time.Duration.ofSeconds(2))
                                                .build()) {
                                    {
                                        setReadTimeout(java.time.Duration.ofSeconds(2));
                                    }
                                })
                        .build();
    }

    private String protect(String text, boolean encrypt) {
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            if (encrypt) {
                byte[] iv = new byte[12];
                new SecureRandom().nextBytes(iv);
                c.init(
                        Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(key, "AES"),
                        new GCMParameterSpec(128, iv));
                byte[] data = c.doFinal(text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                return Base64.getEncoder()
                        .encodeToString(
                                java.nio.ByteBuffer.allocate(iv.length + data.length)
                                        .put(iv)
                                        .put(data)
                                        .array());
            }
            byte[] data = Base64.getDecoder().decode(text);
            c.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, Arrays.copyOf(data, 12)));
            return new String(
                    c.doFinal(Arrays.copyOfRange(data, 12, data.length)),
                    java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception ex) {
            throw new IllegalStateException("Secure delivery encryption failed");
        }
    }

    public void queue(Map<String, Object> request) {
        try {
            db.update(
                    "INSERT INTO"
                            + " iam.secure_deliveries(delivery_id,protected_payload,correlation_id)"
                            + " VALUES (?,?,?)",
                    UUID.randomUUID(),
                    protect(json.writeValueAsString(request), true),
                    org.slf4j.MDC.get("correlationId") == null
                            ? UUID.randomUUID()
                            : UUID.fromString(org.slf4j.MDC.get("correlationId")));
        } catch (tools.jackson.core.JacksonException ex) {
            throw new IllegalStateException("Invalid delivery request");
        }
    }

    public void send(PasswordResetNotification n) {
        queue(
                Map.of(
                        "purpose",
                        "RECOVERY",
                        "email",
                        n.email(),
                        "token",
                        n.token(),
                        "link",
                        n.link()));
    }

    @Scheduled(fixedDelay = 1000)
    public void deliver() {
        if (url.isBlank()) return;
        UUID claim = UUID.randomUUID();
        var jobs =
                db.queryForList(
                        "UPDATE iam.secure_deliveries SET claim_id=?,lease_until=now()+interval '15"
                            + " seconds',attempts=attempts+1 WHERE delivery_id=(SELECT delivery_id"
                            + " FROM iam.secure_deliveries WHERE submitted_at IS NULL AND"
                            + " available_at<=now() AND (lease_until IS NULL OR lease_until<now())"
                            + " ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING"
                            + " delivery_id,protected_payload,correlation_id",
                        claim);
        for (var job : jobs) {
            try {
                http.post()
                        .uri(url)
                        .header("Authorization", "Bearer " + token)
                        .header("Idempotency-Key", job.get("delivery_id").toString())
                        .header("X-Correlation-ID", job.get("correlation_id").toString())
                        .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                        .body(protect(job.get("protected_payload").toString(), false))
                        .retrieve()
                        .toBodilessEntity();
                db.update(
                        "UPDATE iam.secure_deliveries SET"
                                + " submitted_at=now(),protected_payload='',lease_until=NULL WHERE"
                                + " delivery_id=? AND claim_id=?",
                        job.get("delivery_id"),
                        claim);
            } catch (Exception failure) {
                db.update(
                        "UPDATE iam.secure_deliveries SET available_at=now()+interval '30"
                                + " seconds',lease_until=NULL WHERE delivery_id=? AND claim_id=?",
                        job.get("delivery_id"),
                        claim);
            }
        }
    }
}
