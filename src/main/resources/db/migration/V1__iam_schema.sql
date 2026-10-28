-- Initial schema for IAM.

CREATE TABLE iam.delegations (
    delegation_id uuid NOT NULL,
    principal_account_id uuid NOT NULL,
    delegate_account_id uuid NOT NULL,
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    CONSTRAINT delegations_check CHECK ((principal_account_id <> delegate_account_id))
);

CREATE TABLE iam.domain_outbox (
    event_id uuid NOT NULL,
    event_type character varying(80) NOT NULL,
    aggregate_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    published_at timestamp with time zone,
    correlation_id uuid DEFAULT gen_random_uuid() NOT NULL
);

CREATE TABLE iam.identity_audit (
    audit_id uuid NOT NULL,
    actor_id uuid,
    action character varying(80) NOT NULL,
    resource_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    correlation_id uuid DEFAULT gen_random_uuid() NOT NULL
);

CREATE TABLE iam.meter_permission_grants (
    grant_id uuid NOT NULL,
    delegation_id uuid NOT NULL,
    meter_id uuid NOT NULL,
    function character varying(40) NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    CONSTRAINT meter_permission_grants_function_check CHECK (((function)::text = ANY ((ARRAY['VIEW_CONSUMPTION'::character varying, 'VIEW_HISTORY'::character varying, 'VIEW_ALERTS'::character varying, 'USE_REPORTS'::character varying, 'USE_TICKETS'::character varying, 'USE_VISITS'::character varying])::text[])))
);

CREATE TABLE iam.one_time_tokens (
    token_id uuid DEFAULT gen_random_uuid() NOT NULL,
    account_id uuid NOT NULL,
    token_hash character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    purpose character varying(30) DEFAULT 'RECOVERY'::character varying NOT NULL,
    CONSTRAINT one_time_tokens_purpose_check CHECK (((purpose)::text = ANY ((ARRAY['ACTIVATION'::character varying, 'RECOVERY'::character varying])::text[])))
);

CREATE TABLE iam.password_credentials (
    credential_id uuid NOT NULL,
    account_id uuid NOT NULL,
    password_hash character varying(255) NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE iam.purchase_receipts (
    purchase_order_id uuid NOT NULL,
    event_id uuid NOT NULL,
    account_id uuid NOT NULL,
    email character varying(254) NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE iam.secure_deliveries (
    delivery_id uuid NOT NULL,
    protected_payload text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    available_at timestamp with time zone DEFAULT now() NOT NULL,
    submitted_at timestamp with time zone,
    lease_until timestamp with time zone,
    claim_id uuid,
    attempts integer DEFAULT 0 NOT NULL,
    correlation_id uuid DEFAULT gen_random_uuid() NOT NULL
);

CREATE TABLE iam.user_accounts (
    account_id uuid DEFAULT gen_random_uuid() NOT NULL,
    email character varying(254) NOT NULL,
    role character varying(20) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    account_kind character varying(20) DEFAULT 'PRINCIPAL'::character varying NOT NULL,
    account_status character varying(25) DEFAULT 'ACTIVE'::character varying NOT NULL,
    activated_at timestamp with time zone,
    session_version bigint DEFAULT 0 NOT NULL,
    CONSTRAINT account_role_check CHECK (((role)::text = ANY ((ARRAY['USER'::character varying, 'SUPERADMIN'::character varying])::text[]))),
    CONSTRAINT user_accounts_account_kind_check CHECK (((account_kind)::text = ANY ((ARRAY['PRINCIPAL'::character varying, 'DELEGATED'::character varying])::text[]))),
    CONSTRAINT user_accounts_account_status_check CHECK (((account_status)::text = ANY ((ARRAY['PENDING_ACTIVATION'::character varying, 'ACTIVE'::character varying, 'DISABLED'::character varying])::text[])))
);

CREATE TABLE iam.user_profiles (
    profile_id uuid DEFAULT gen_random_uuid() NOT NULL,
    account_id uuid NOT NULL,
    first_name character varying(100) NOT NULL,
    last_name character varying(100) NOT NULL,
    phone character varying(20),
    address character varying(255),
    display_name character varying(201) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY iam.user_accounts
    ADD CONSTRAINT account_email_key UNIQUE (email);

ALTER TABLE ONLY iam.user_accounts
    ADD CONSTRAINT account_pkey PRIMARY KEY (account_id);

ALTER TABLE ONLY iam.delegations
    ADD CONSTRAINT delegations_delegate_account_id_key UNIQUE (delegate_account_id);

ALTER TABLE ONLY iam.delegations
    ADD CONSTRAINT delegations_pkey PRIMARY KEY (delegation_id);

ALTER TABLE ONLY iam.domain_outbox
    ADD CONSTRAINT domain_outbox_pkey PRIMARY KEY (event_id);

ALTER TABLE ONLY iam.identity_audit
    ADD CONSTRAINT identity_audit_pkey PRIMARY KEY (audit_id);

ALTER TABLE ONLY iam.meter_permission_grants
    ADD CONSTRAINT meter_permission_grants_pkey PRIMARY KEY (grant_id);

ALTER TABLE ONLY iam.password_credentials
    ADD CONSTRAINT password_credentials_account_id_key UNIQUE (account_id);

ALTER TABLE ONLY iam.password_credentials
    ADD CONSTRAINT password_credentials_pkey PRIMARY KEY (credential_id);

ALTER TABLE ONLY iam.user_profiles
    ADD CONSTRAINT profile_id_account_key UNIQUE (account_id);

ALTER TABLE ONLY iam.user_profiles
    ADD CONSTRAINT profile_pkey PRIMARY KEY (profile_id);

ALTER TABLE ONLY iam.purchase_receipts
    ADD CONSTRAINT purchase_receipts_event_id_key UNIQUE (event_id);

ALTER TABLE ONLY iam.purchase_receipts
    ADD CONSTRAINT purchase_receipts_pkey PRIMARY KEY (purchase_order_id);

ALTER TABLE ONLY iam.one_time_tokens
    ADD CONSTRAINT recovery_password_pkey PRIMARY KEY (token_id);

ALTER TABLE ONLY iam.secure_deliveries
    ADD CONSTRAINT secure_deliveries_pkey PRIMARY KEY (delivery_id);

CREATE UNIQUE INDEX active_grant_uq ON iam.meter_permission_grants USING btree (delegation_id, meter_id, function) WHERE (revoked_at IS NULL);

CREATE INDEX delivery_pending ON iam.secure_deliveries USING btree (available_at) WHERE (submitted_at IS NULL);

CREATE INDEX idx_recovery_id_account ON iam.one_time_tokens USING btree (account_id);

CREATE INDEX idx_recovery_token_hash ON iam.one_time_tokens USING btree (token_hash);

CREATE UNIQUE INDEX one_time_token_hash_uq ON iam.one_time_tokens USING btree (token_hash);

CREATE UNIQUE INDEX user_account_normalized_email_uq ON iam.user_accounts USING btree (lower((email)::text));

ALTER TABLE ONLY iam.delegations
    ADD CONSTRAINT delegations_delegate_account_id_fkey FOREIGN KEY (delegate_account_id) REFERENCES iam.user_accounts(account_id);

ALTER TABLE ONLY iam.delegations
    ADD CONSTRAINT delegations_principal_account_id_fkey FOREIGN KEY (principal_account_id) REFERENCES iam.user_accounts(account_id);

ALTER TABLE ONLY iam.meter_permission_grants
    ADD CONSTRAINT meter_permission_grants_delegation_id_fkey FOREIGN KEY (delegation_id) REFERENCES iam.delegations(delegation_id);

ALTER TABLE ONLY iam.password_credentials
    ADD CONSTRAINT password_credentials_account_id_fkey FOREIGN KEY (account_id) REFERENCES iam.user_accounts(account_id);

ALTER TABLE ONLY iam.user_profiles
    ADD CONSTRAINT profile_id_account_fkey FOREIGN KEY (account_id) REFERENCES iam.user_accounts(account_id) ON DELETE CASCADE;

ALTER TABLE ONLY iam.purchase_receipts
    ADD CONSTRAINT purchase_receipts_account_id_fkey FOREIGN KEY (account_id) REFERENCES iam.user_accounts(account_id);

ALTER TABLE ONLY iam.one_time_tokens
    ADD CONSTRAINT recovery_password_id_account_fkey FOREIGN KEY (account_id) REFERENCES iam.user_accounts(account_id) ON DELETE CASCADE;
