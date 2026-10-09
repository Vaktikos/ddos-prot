-- MFA (TOTP) state per user. The secret is stored encrypted (AES-GCM, see internal/panel/mfa.go).
-- totp_last_step records the last accepted time step, so one code cannot be replayed.
ALTER TABLE users
    ADD COLUMN totp_secret_enc text,
    ADD COLUMN totp_enabled boolean NOT NULL DEFAULT false,
    ADD COLUMN totp_last_step bigint NOT NULL DEFAULT 0;

-- Service-level incidents (for example connection-rate attacks on one port).
ALTER TABLE incidents ADD COLUMN service text NOT NULL DEFAULT '';
