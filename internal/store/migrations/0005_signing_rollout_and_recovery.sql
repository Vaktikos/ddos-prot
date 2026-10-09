-- Which panel signing keys a node currently trusts, reported with each heartbeat. The panel
-- uses it to tell an administrator when every node knows the next key and rotation is safe.
ALTER TABLE nodes ADD COLUMN trusted_key_ids text[] NOT NULL DEFAULT '{}';

-- One-time MFA recovery codes. Only a SHA-256 of each code is stored.
CREATE TABLE mfa_recovery_codes (
    id        bigserial PRIMARY KEY,
    user_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash bytea NOT NULL,
    used_at   timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, code_hash)
);
CREATE INDEX mfa_recovery_codes_user_idx ON mfa_recovery_codes (user_id) WHERE used_at IS NULL;
