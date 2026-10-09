-- Sentinel Shield initial schema.
-- Conventions: timestamps are timestamptz, IDs are uuid, time-series tables are keyed
-- by (entity, ts) and indexed on ts for range queries.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Users and sessions -----------------------------------------------------------

CREATE TABLE users (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email         text NOT NULL UNIQUE CHECK (char_length(email) BETWEEN 3 AND 254),
    password_hash text NOT NULL,
    role          text NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
    disabled      boolean NOT NULL DEFAULT false,
    failed_logins integer NOT NULL DEFAULT 0,
    locked_until  timestamptz,
    last_login_at timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- Only a SHA-256 of the session token is stored; a database leak does not expose sessions.
CREATE TABLE sessions (
    token_hash   bytea PRIMARY KEY,
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token   text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    client_ip    inet
);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

-- Audit trail for all security-relevant actions, including agent-originated events.
CREATE TABLE audit_log (
    id          bigserial PRIMARY KEY,
    ts          timestamptz NOT NULL DEFAULT now(),
    actor_type  text NOT NULL CHECK (actor_type IN ('user', 'node', 'system')),
    actor_id    text NOT NULL,
    action      text NOT NULL,
    target_type text,
    target_id   text,
    details     jsonb NOT NULL DEFAULT '{}'::jsonb,
    client_ip   inet
);
CREATE INDEX audit_log_ts_idx ON audit_log (ts DESC);

-- Locations and nodes ----------------------------------------------------------

CREATE TABLE locations (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 100),
    description text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE nodes (
    id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                   text NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 100),
    location_id            uuid REFERENCES locations(id) ON DELETE SET NULL,
    status                 text NOT NULL DEFAULT 'pending'
                           CHECK (status IN ('pending', 'online', 'offline', 'degraded', 'revoked')),
    mode                   text NOT NULL DEFAULT 'dry_run' CHECK (mode IN ('dry_run', 'approval', 'auto')),
    public_key             bytea,
    enrollment_hash        bytea,
    enrollment_expires_at  timestamptz,
    hostname               text NOT NULL DEFAULT '',
    agent_version          text NOT NULL DEFAULT '',
    management_cidrs       cidr[] NOT NULL DEFAULT '{}',
    health                 jsonb NOT NULL DEFAULT '{}'::jsonb,
    applied_policy_version bigint NOT NULL DEFAULT 0,
    desired_policy_version bigint NOT NULL DEFAULT 0,
    sync_status            text NOT NULL DEFAULT 'never'
                           CHECK (sync_status IN ('never', 'pending', 'synced', 'failed')),
    sync_error             text NOT NULL DEFAULT '',
    last_heartbeat_at      timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX nodes_status_idx ON nodes (status);

-- Replay protection for signed agent requests. Rows expire and are purged periodically.
CREATE TABLE agent_nonces (
    node_id    uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    nonce      text NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (node_id, nonce)
);
CREATE INDEX agent_nonces_expires_idx ON agent_nonces (expires_at);

-- Protection profiles, targets and services -------------------------------------

CREATE TABLE protection_profiles (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 100),
    kind       text NOT NULL CHECK (kind IN ('generic', 'minecraft_java', 'minecraft_bedrock', 'web')),
    config     jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE protected_targets (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id    uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    name       text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    prefix     cidr NOT NULL,
    profile_id uuid NOT NULL REFERENCES protection_profiles(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (node_id, prefix)
);

CREATE TABLE services (
    id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id uuid NOT NULL REFERENCES protected_targets(id) ON DELETE CASCADE,
    name      text NOT NULL DEFAULT '',
    protocol  text NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    port      integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    UNIQUE (target_id, protocol, port)
);

-- Allow and deny rules -------------------------------------------------------------

CREATE TABLE rules (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id    uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    kind       text NOT NULL CHECK (kind IN ('allow', 'deny')),
    prefix     cidr NOT NULL,
    reason     text NOT NULL CHECK (char_length(reason) BETWEEN 3 AND 500),
    expires_at timestamptz,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    revoked_by uuid REFERENCES users(id) ON DELETE SET NULL,
    CHECK (kind = 'allow' OR expires_at IS NOT NULL)
);
CREATE INDEX rules_node_active_idx ON rules (node_id) WHERE revoked_at IS NULL;

CREATE TABLE rule_events (
    id       bigserial PRIMARY KEY,
    rule_id  uuid NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    ts       timestamptz NOT NULL DEFAULT now(),
    action   text NOT NULL,
    actor_id text NOT NULL,
    details  jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX rule_events_rule_idx ON rule_events (rule_id, ts);

-- Versioned policies. Each row is the exact signed body the agent verifies.
CREATE TABLE policy_versions (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id    uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    version    bigint NOT NULL CHECK (version > 0),
    body       text NOT NULL,
    sha256     text NOT NULL,
    signature  text NOT NULL,
    note       text NOT NULL DEFAULT '',
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (node_id, version)
);

-- Time-series metrics ---------------------------------------------------------------

CREATE TABLE node_metrics (
    node_id          uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    ts               timestamptz NOT NULL,
    cpu_percent      double precision NOT NULL,
    mem_used_percent double precision NOT NULL,
    rx_bps           double precision NOT NULL,
    tx_bps           double precision NOT NULL,
    rx_pps           double precision NOT NULL,
    tx_pps           double precision NOT NULL,
    dynamic_entries  integer NOT NULL DEFAULT 0,
    PRIMARY KEY (node_id, ts)
);
CREATE INDEX node_metrics_ts_idx ON node_metrics (ts);

CREATE TABLE target_metrics (
    target_id   uuid NOT NULL REFERENCES protected_targets(id) ON DELETE CASCADE,
    ts          timestamptz NOT NULL,
    pps         double precision NOT NULL,
    bps         double precision NOT NULL,
    syn_pps     double precision NOT NULL,
    udp_pps     double precision NOT NULL,
    icmp_pps    double precision NOT NULL,
    dropped_pps double precision NOT NULL,
    PRIMARY KEY (target_id, ts)
);
CREATE INDEX target_metrics_ts_idx ON target_metrics (ts);

-- Incidents, mitigation and events from agents ---------------------------------------

-- Raw journal of everything agents report. event_id is unique per node, so retransmits are idempotent.
CREATE TABLE agent_events (
    node_id  uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    event_id text NOT NULL,
    type     text NOT NULL,
    action   text NOT NULL,
    ts       timestamptz NOT NULL,
    payload  jsonb NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (node_id, event_id)
);
CREATE INDEX agent_events_ts_idx ON agent_events (ts DESC);

CREATE TABLE incidents (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id         uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    agent_incident_id text NOT NULL,
    target_prefix   cidr NOT NULL,
    category        text NOT NULL,
    verdict         text NOT NULL CHECK (verdict IN ('traffic_spike', 'suspicious_anomaly', 'confirmed_attack')),
    status          text NOT NULL CHECK (status IN ('open', 'closed')),
    started_at      timestamptz NOT NULL,
    ended_at        timestamptz,
    peak_pps        double precision NOT NULL DEFAULT 0,
    peak_bps        double precision NOT NULL DEFAULT 0,
    peak_syn_pps    double precision NOT NULL DEFAULT 0,
    peak_udp_pps    double precision NOT NULL DEFAULT 0,
    peak_icmp_pps   double precision NOT NULL DEFAULT 0,
    confidence      double precision NOT NULL DEFAULT 0,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (node_id, agent_incident_id)
);
CREATE INDEX incidents_started_idx ON incidents (started_at DESC);
CREATE INDEX incidents_status_idx ON incidents (status) WHERE status = 'open';

CREATE TABLE mitigation_actions (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id           uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    agent_action_id   text NOT NULL,
    incident_id       uuid REFERENCES incidents(id) ON DELETE SET NULL,
    kind              text NOT NULL,
    target_prefix     cidr NOT NULL,
    rate              integer NOT NULL DEFAULT 0,
    auto_block_seconds integer NOT NULL DEFAULT 0,
    status            text NOT NULL CHECK (status IN
                      ('proposed', 'pending_approval', 'approved', 'applied', 'rejected', 'expired', 'removed')),
    dry_run           boolean NOT NULL DEFAULT false,
    reason            text NOT NULL DEFAULT '',
    decided_by        uuid REFERENCES users(id) ON DELETE SET NULL,
    decided_at        timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (node_id, agent_action_id)
);
CREATE INDEX mitigation_status_idx ON mitigation_actions (status) WHERE status IN ('pending_approval', 'approved');

CREATE TABLE alerts (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id         uuid REFERENCES nodes(id) ON DELETE CASCADE,
    severity        text NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    source          text NOT NULL,
    title           text NOT NULL,
    message         text NOT NULL DEFAULT '',
    dedupe_key      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    acknowledged_at timestamptz,
    acknowledged_by uuid REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX alerts_created_idx ON alerts (created_at DESC);
-- At most one unacknowledged alert per dedupe key, so repeated conditions do not flood operators.
CREATE UNIQUE INDEX alerts_open_dedupe_idx ON alerts (dedupe_key)
    WHERE acknowledged_at IS NULL AND dedupe_key IS NOT NULL;
