-- State of the reverse-proxy reject logs a node follows, reported with each heartbeat.
ALTER TABLE nodes ADD COLUMN l7 jsonb NOT NULL DEFAULT '[]'::jsonb;
