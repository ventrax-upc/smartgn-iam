package com.smartgn.iam.profile.infrastructure.persistence;

import com.smartgn.iam.profile.application.port.out.ProfileRepository;
import com.smartgn.iam.profile.domain.model.UserProfile;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.*;

@Repository
public class JdbcProfileRepository implements ProfileRepository {
    private final JdbcTemplate db;

    public JdbcProfileRepository(JdbcTemplate db) {
        this.db = db;
    }

    private Optional<UserProfile> find(String key, UUID id) {
        return db
                .query(
                        "SELECT * FROM iam.user_profiles WHERE " + key + "=?",
                        (s, n) ->
                                UserProfile.restore(
                                        s.getObject("profile_id", UUID.class),
                                        s.getObject("account_id", UUID.class),
                                        s.getString("first_name"),
                                        s.getString("last_name"),
                                        s.getString("phone"),
                                        s.getString("address")),
                        id)
                .stream()
                .findFirst();
    }

    public boolean existsByAccountId(UUID id) {
        return findByAccountId(id).isPresent();
    }

    public Optional<UserProfile> findById(UUID id) {
        return find("profile_id", id);
    }

    public Optional<UserProfile> findByAccountId(UUID id) {
        return find("account_id", id);
    }

    public UserProfile save(UserProfile p) {
        db.update(
                "INSERT INTO"
                    + " iam.user_profiles(profile_id,account_id,first_name,last_name,display_name,phone,address)"
                    + " VALUES (?,?,?,?,?,?,?) ON CONFLICT(profile_id) DO UPDATE SET"
                    + " first_name=EXCLUDED.first_name,last_name=EXCLUDED.last_name,display_name=EXCLUDED.display_name,phone=EXCLUDED.phone,address=EXCLUDED.address,updated_at=now()",
                p.getId(),
                p.getAccountId(),
                p.getFirstName(),
                p.getLastName(),
                p.getFirstName() + " " + p.getLastName(),
                p.getPhone(),
                p.getAddress());
        return p;
    }
}
