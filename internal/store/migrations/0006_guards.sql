-- State of the Minecraft guards on a node, reported with each heartbeat.
ALTER TABLE nodes ADD COLUMN guards jsonb NOT NULL DEFAULT '[]'::jsonb;
