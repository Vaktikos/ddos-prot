export interface User {
  id: string;
  email: string;
  role: "viewer" | "operator" | "admin";
}

export interface Node {
  id: string;
  name: string;
  location_name: string | null;
  status: "pending" | "online" | "offline" | "degraded" | "revoked";
  mode: "dry_run" | "approval" | "auto";
  hostname: string;
  agent_version: string;
  management_cidrs: string[];
  health: { status?: string; errors?: string[] };
  applied_policy_version: number;
  desired_policy_version: number;
  sync_status: "never" | "pending" | "synced" | "failed";
  sync_error: string;
  last_heartbeat_at: string | null;
  enrolled: boolean;
  created_at: string;
}

export interface Service {
  name: string;
  protocol: "tcp" | "udp";
  port: number;
}

export interface Target {
  id: string;
  name: string;
  prefix: string;
  profile: string;
  services: Service[];
  pps: number | null;
  bps: number | null;
  syn_pps: number | null;
  dropped_pps: number | null;
  measured_at: string | null;
}

export interface Rule {
  id: string;
  kind: "allow" | "deny";
  prefix: string;
  reason: string;
  expires_at: string | null;
  created_at: string;
  revoked_at: string | null;
}

export interface PolicyVersion {
  version: number;
  sha256: string;
  note: string;
  created_by: string;
  created_at: string;
}

export interface Profile {
  id: string;
  name: string;
  kind: string;
  config: {
    total_pps: number;
    syn_pps: number;
    udp_pps: number;
    icmp_pps: number;
    confirm_seconds: number;
    clear_seconds: number;
    mitigation: { syn_rate_per_source: number; udp_rate_per_source: number; auto_block_seconds: number };
  };
}

export interface Incident {
  id: string;
  node_name: string;
  target: string;
  category: string;
  verdict: "traffic_spike" | "suspicious_anomaly" | "confirmed_attack";
  status: "open" | "closed";
  started_at: string;
  ended_at: string | null;
  peak_pps: number;
  peak_bps: number;
  peak_syn_pps: number;
  peak_udp_pps: number;
  peak_icmp_pps: number;
  confidence: number;
}

export interface Action {
  id: string;
  node_name: string;
  kind: string;
  target: string;
  rate: number;
  auto_block_seconds: number;
  status: string;
  dry_run: boolean;
  reason: string;
  created_at: string;
  decided_at: string | null;
  decided_by: string | null;
}

export interface Alert {
  id: string;
  node_id: string | null;
  severity: "info" | "warning" | "critical";
  source: string;
  title: string;
  message: string;
  created_at: string;
  acknowledged_at: string | null;
}

export interface Dashboard {
  generated_at: string;
  nodes: Record<string, number>;
  protected_targets: number;
  throughput_gbps: number;
  pps: number;
  dropped_pps: number;
  open_incidents: number;
  confirmed_open: number;
  incidents_24h: number;
  active_mitigations: number;
  pending_approvals: number;
  active_blocks: number;
  unacked_alerts: number;
  node_details: {
    id: string;
    name: string;
    status: string;
    cpu_percent: number | null;
    mem_percent: number | null;
    gbps: number | null;
    pps: number | null;
    sampled_at: string | null;
    applied_policy_version: number;
    desired_policy_version: number;
    sync_status: string;
  }[];
  target_details: {
    id: string;
    name: string;
    prefix: string;
    node_name: string;
    gbps: number | null;
    pps: number | null;
    syn_pps: number | null;
    dropped_pps: number | null;
    sampled_at: string | null;
  }[];
}

export interface SeriesPoint {
  ts: string;
  gbps?: number;
  pps?: number;
  cpu_percent?: number;
  mem_percent?: number;
  syn_pps?: number;
  dropped_pps?: number;
}
