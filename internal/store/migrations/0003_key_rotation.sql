-- Admin-requested rotation of a node's Ed25519 key. The agent performs the rotation at its
-- next heartbeat, proving possession of the old key; the flag then clears.
ALTER TABLE nodes ADD COLUMN rotate_key_requested boolean NOT NULL DEFAULT false;
