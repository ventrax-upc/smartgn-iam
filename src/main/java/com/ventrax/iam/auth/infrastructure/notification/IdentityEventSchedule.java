package com.ventrax.iam.auth.infrastructure.notification;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.*;

@Component
public class IdentityEventSchedule {
    private final JdbcTemplate db;
    private final String url, token;
    private final RestClient http;

    public IdentityEventSchedule(
            JdbcTemplate db,
            @Value("${IDENTITY_EVENT_SINK_URL:}") String url,
            @Value("${IDENTITY_EVENT_SINK_TOKEN:}") String token) {
        this.db = db;
        this.url = url;
        this.token = token;
        var f =
                new org.springframework.http.client.JdkClientHttpRequestFactory(
                        java.net.http.HttpClient.newBuilder()
                                .connectTimeout(java.time.Duration.ofSeconds(2))
                                .build());
        f.setReadTimeout(java.time.Duration.ofSeconds(2));
        http = RestClient.builder().requestFactory(f).build();
    }

    @Scheduled(fixedDelay = 1000)
    public void publish() {
        if (url.isBlank()) return;
        for (var row :
                db.queryForList(
                        "SELECT event_id,event_type,aggregate_id,correlation_id FROM"
                            + " iam.domain_outbox WHERE published_at IS NULL ORDER BY created_at"
                            + " LIMIT 10"))
            try {
                http.post()
                        .uri(url)
                        .header("Authorization", "Bearer " + token)
                        .header("Idempotency-Key", row.get("event_id").toString())
                        .header("X-Correlation-ID", row.get("correlation_id").toString())
                        .body(row)
                        .retrieve()
                        .toBodilessEntity();
                db.update(
                        "UPDATE iam.domain_outbox SET published_at=now() WHERE event_id=? AND"
                                + " published_at IS NULL",
                        row.get("event_id"));
            } catch (Exception unavailable) {
                return;
            }
    }
}
