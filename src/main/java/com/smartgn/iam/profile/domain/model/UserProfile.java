package com.smartgn.iam.profile.domain.model;

import java.util.UUID;

public class UserProfile {

    private UUID id = UUID.randomUUID();

    private UUID accountId;

    private String firstName;

    private String lastName;

    private String phone;

    private String address;

    protected UserProfile() {
        // Reconstruction constructor
    }

    private UserProfile(
            UUID accountId, String firstName, String lastName, String phone, String address) {
        this.accountId = accountId;
        assign(firstName, lastName, phone, address);
    }

    public static UserProfile create(
            UUID accountId, String firstName, String lastName, String phone, String address) {
        return new UserProfile(accountId, firstName, lastName, phone, address);
    }

    /** Full replacement: first and last names are required; phone and address are optional. */
    public void update(String firstName, String lastName, String phone, String address) {
        assign(firstName, lastName, phone, address);
    }

    public boolean belongsTo(UUID accountId) {
        return this.accountId.equals(accountId);
    }

    private void assign(String firstName, String lastName, String phone, String address) {
        this.firstName = required(firstName, "first name");
        this.lastName = required(lastName, "last name");
        this.phone = optional(phone);
        this.address = optional(address);
    }

    private static String required(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.trim();
    }

    private static String optional(String value) {
        return (value == null || value.isBlank()) ? null : value.trim();
    }

    public static UserProfile restore(
            UUID id, UUID account, String first, String last, String phone, String address) {
        UserProfile p = new UserProfile(account, first, last, phone, address);
        p.id = id;
        return p;
    }

    public UUID getId() {
        return id;
    }

    public UUID getAccountId() {
        return accountId;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public String getPhone() {
        return phone;
    }

    public String getAddress() {
        return address;
    }
}
