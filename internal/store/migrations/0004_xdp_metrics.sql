-- Packets per second dropped by the XDP filter on the node, reported with each heartbeat.
ALTER TABLE node_metrics ADD COLUMN xdp_dropped_pps double precision NOT NULL DEFAULT 0;
