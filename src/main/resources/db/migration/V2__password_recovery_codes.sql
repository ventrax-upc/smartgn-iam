CREATE TABLE iam.password_recovery_codes (
    account_id uuid PRIMARY KEY REFERENCES iam.user_accounts(account_id),
    challenge_id uuid NOT NULL UNIQUE,
    code_hash text NOT NULL,
    attempts integer NOT NULL DEFAULT 0,
    expires_at timestamptz NOT NULL,
    verified_at timestamptz
);
