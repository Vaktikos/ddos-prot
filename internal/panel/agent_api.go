package panel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/vaktikos/ddos-prot/internal/agent"
	"github.com/vaktikos/ddos-prot/internal/detect"
	"github.com/vaktikos/ddos-prot/internal/identity"
	"github.com/vaktikos/ddos-prot/internal/mitigate"
	"github.com/vaktikos/ddos-prot/internal/policy"
)

const maxAgentBody = 4 << 20

type enrollRequest struct {
	Token     string `json:"token"`
	PublicKey string `json:"public_key"`
	Hostname  string `json:"hostname"`
	Version   string `json:"version"`
}

// enroll consumes a one-time token and binds the node to the agent's public key.
// The token is stored only as a hash and is invalid after first use or expiry.
func (a *App) enroll(w http.ResponseWriter, r *http.Request) {
	if !a.loginRL.allow("enroll:" + clientIP(r).String()) {
		writeErr(w, http.StatusTooManyRequests, "zu viele Anfragen")
		return
	}
	var req enrollRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	pub, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize || req.Token == "" {
		writeErr(w, http.StatusBadRequest, "ungültiger schlüssel oder token")
		return
	}
	ctx := r.Context()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	defer tx.Rollback(ctx)
	var nodeID string
	err = tx.QueryRow(ctx, `UPDATE nodes SET public_key = $2, enrollment_hash = NULL, enrollment_expires_at = NULL,
		hostname = left($3, 255), agent_version = left($4, 64), status = 'pending', updated_at = now()
		WHERE enrollment_hash = $1 AND enrollment_expires_at > now() AND public_key IS NULL AND status <> 'revoked'
		RETURNING id::text`, tokenHash(req.Token), []byte(pub), req.Hostname, req.Version).Scan(&nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeErr(w, http.StatusUnauthorized, "token ungültig, bereits verwendet oder abgelaufen")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	a.audit(ctx, tx, "node", nodeID, "node.enroll", "node", nodeID, map[string]any{"hostname": req.Hostname, "version": req.Version}, ipString(r))
	if err := tx.Commit(ctx); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id":           nodeID,
		"panel_public_key":  base64.StdEncoding.EncodeToString(a.pub),
		"panel_public_keys": []string{base64.StdEncoding.EncodeToString(a.pub)},
	})
}

// authenticateAgent verifies the request signature and records the nonce. It returns
// the node ID, or writes an error response and returns false.
func (a *App) authenticateAgent(w http.ResponseWriter, r *http.Request, body []byte) (string, bool) {
	ctx := r.Context()
	nodeID := r.Header.Get(identity.HeaderNode)
	var pub []byte
	var status string
	err := a.db.QueryRow(ctx, `SELECT public_key, status FROM nodes WHERE id::text = $1`, nodeID).Scan(&pub, &status)
	if err != nil || pub == nil {
		writeErr(w, http.StatusUnauthorized, "unbekannter node")
		return "", false
	}
	if status == "revoked" {
		writeErr(w, http.StatusForbidden, "node ist widerrufen")
		return "", false
	}
	if !a.agentRL.allow(nodeID) {
		writeErr(w, http.StatusTooManyRequests, "zu viele Anfragen")
		return "", false
	}
	v, err := identity.Verify(r, body, ed25519.PublicKey(pub), a.now())
	if err != nil {
		a.log.Warn("agent-signatur abgelehnt", "node", nodeID, "err", err)
		writeErr(w, http.StatusUnauthorized, "signatur ungültig")
		return "", false
	}
	tag, err := a.db.Exec(ctx, `INSERT INTO agent_nonces (node_id, nonce, expires_at) VALUES ($1::uuid, $2, $3)
		ON CONFLICT DO NOTHING`, nodeID, v.Nonce, v.Expiry)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return "", false
	}
	if tag.RowsAffected() == 0 {
		writeErr(w, http.StatusUnauthorized, "replay erkannt")
		return "", false
	}
	return nodeID, true
}

// heartbeat authenticates the node, stores its status and metrics, processes its
// outbox events idempotently and answers with the desired policy version.
func (a *App) heartbeat(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAgentBody))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "body nicht lesbar")
		return
	}
	nodeID, ok := a.authenticateAgent(w, r, body)
	if !ok {
		return
	}
	var hb agent.Heartbeat
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&hb); err != nil {
		writeErr(w, http.StatusBadRequest, "heartbeat ungültig: "+err.Error())
		return
	}
	ctx := r.Context()
	now := a.now()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	defer tx.Rollback(ctx)

	healthJSON, _ := json.Marshal(hb.Health)
	status := "online"
	if hb.Health.Status == "degraded" {
		status = "degraded"
	}
	var desired int64
	var rotate bool
	err = tx.QueryRow(ctx, `UPDATE nodes SET
		status = $2, hostname = left($3, 255), agent_version = left($4, 64), health = $5::jsonb,
		applied_policy_version = $6, last_heartbeat_at = $7, updated_at = $7,
		sync_status = CASE WHEN $6 >= desired_policy_version THEN 'synced'
		                   WHEN $8 <> '' THEN 'failed' ELSE 'pending' END,
		sync_error = CASE WHEN $6 >= desired_policy_version THEN '' ELSE left($8, 500) END
		WHERE id = $1::uuid
		RETURNING desired_policy_version, rotate_key_requested`,
		nodeID, status, hb.Hostname, hb.AgentVersion, string(healthJSON), hb.AppliedPolicyVersion, now, hb.PolicyError).Scan(&desired, &rotate)
	if err == nil {
		guards := hb.Guards
		if len(guards) > 16 {
			guards = guards[:16]
		}
		if guards == nil {
			guards = []agent.GuardReport{}
		}
		guardsJSON, _ := json.Marshal(guards)
		_, err = tx.Exec(ctx, `UPDATE nodes SET trusted_key_ids = $2::text[], guards = $3::jsonb WHERE id = $1::uuid`,
			nodeID, normalizeKeyIDs(hb.TrustedKeyIDs), string(guardsJSON))
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}

	if _, err := tx.Exec(ctx, `INSERT INTO node_metrics
		(node_id, ts, cpu_percent, mem_used_percent, rx_bps, tx_bps, rx_pps, tx_pps, dynamic_entries, xdp_dropped_pps)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (node_id, ts) DO NOTHING`,
		nodeID, now, hb.Host.CPUPercent, hb.Host.MemUsedPct, hb.Host.RxBps, hb.Host.TxBps,
		hb.Host.RxPPS, hb.Host.TxPPS, hb.DynamicEntries, hb.Host.XDPDropPPS); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	for _, t := range hb.Targets {
		if _, err := tx.Exec(ctx, `INSERT INTO target_metrics (target_id, ts, pps, bps, syn_pps, udp_pps, icmp_pps, dropped_pps)
			SELECT t.id, $3, $4, $5, $6, $7, $8, $9 FROM protected_targets t
			WHERE t.node_id = $1::uuid AND t.prefix = $2::cidr
			ON CONFLICT (target_id, ts) DO NOTHING`,
			nodeID, t.Prefix, now, t.PPS, t.BPS, t.SYNPPS, t.UDPPPS, t.ICMPPPS, t.DroppedPPS); err != nil {
			writeErr(w, http.StatusInternalServerError, "interner Fehler")
			return
		}
	}

	for _, p := range hb.Mitigations {
		if p.Status == mitigate.StatusApplied {
			if _, err := tx.Exec(ctx, `UPDATE mitigation_actions SET status = 'applied', updated_at = now()
				WHERE node_id = $1::uuid AND agent_action_id = $2 AND status = 'approved'`, nodeID, p.ID); err != nil {
				writeErr(w, http.StatusInternalServerError, "interner Fehler")
				return
			}
		}
	}

	for _, ev := range hb.Events {
		payload, err := json.Marshal(ev.Payload)
		if err != nil {
			continue
		}
		tag, err := tx.Exec(ctx, `INSERT INTO agent_events (node_id, event_id, type, action, ts, payload)
			VALUES ($1::uuid, $2, $3, $4, $5, $6::jsonb) ON CONFLICT DO NOTHING`,
			nodeID, ev.ID, ev.Type, ev.Action, ev.At, string(payload))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "interner Fehler")
			return
		}
		if tag.RowsAffected() == 1 { // retransmitted events have no further effect
			a.applyEventIsolated(ctx, tx, nodeID, ev, payload)
		}
	}

	reply, err := a.heartbeatReply(ctx, tx, nodeID, desired)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	reply.RotateKey = rotate
	reply.TrustKeys = &a.keyset
	if err := tx.Commit(ctx); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	writeJSON(w, http.StatusOK, reply)
}

// applyEventIsolated applies one event inside a savepoint. A failing statement would
// otherwise abort the whole heartbeat transaction; the agent would resend the same event
// forever, so one bad event could block all later heartbeats. The event stays recorded in
// agent_events either way.
func (a *App) applyEventIsolated(ctx context.Context, tx pgx.Tx, nodeID string, ev agent.Event, payload []byte) {
	sp, err := tx.Begin(ctx)
	if err != nil {
		a.log.Error("savepoint nicht möglich", "node", nodeID, "err", err)
		return
	}
	if err := a.applyEvent(ctx, sp, nodeID, ev, payload); err != nil {
		_ = sp.Rollback(ctx)
		a.log.Error("agent-ereignis nicht verarbeitbar", "node", nodeID, "type", ev.Type, "action", ev.Action, "err", err)
		return
	}
	if err := sp.Commit(ctx); err != nil {
		a.log.Error("savepoint-commit fehlgeschlagen", "node", nodeID, "err", err)
	}
}

func (a *App) heartbeatReply(ctx context.Context, tx pgx.Tx, nodeID string, desired int64) (agent.HeartbeatReply, error) {
	reply := agent.HeartbeatReply{DesiredPolicyVersion: desired, ServerTime: a.now(),
		ApprovedPlanIDs: []string{}, RejectedPlanIDs: []string{}}
	rows, err := tx.Query(ctx, `SELECT agent_action_id, status FROM mitigation_actions
		WHERE node_id = $1::uuid AND (status = 'approved' OR (status = 'rejected' AND decided_at > now() - interval '10 minutes'))`, nodeID)
	if err != nil {
		return reply, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, status string
		if err := rows.Scan(&id, &status); err != nil {
			return reply, err
		}
		if status == "approved" {
			reply.ApprovedPlanIDs = append(reply.ApprovedPlanIDs, id)
		} else {
			reply.RejectedPlanIDs = append(reply.RejectedPlanIDs, id)
		}
	}
	return reply, rows.Err()
}

// applyEvent turns one agent event into panel state. It runs once per event ID.
func (a *App) applyEvent(ctx context.Context, tx pgx.Tx, nodeID string, ev agent.Event, payload []byte) error {
	switch ev.Type {
	case "incident":
		return a.applyIncident(ctx, tx, nodeID, ev.Action, payload)
	case "mitigation":
		return a.applyMitigation(ctx, tx, nodeID, ev.Action, payload)
	case "alert":
		var p struct {
			IncidentID string  `json:"incident_id"`
			Target     string  `json:"target"`
			Category   string  `json:"category"`
			PeakPPS    float64 `json:"peak_pps"`
			Note       string  `json:"note"`
		}
		_ = json.Unmarshal(payload, &p)
		// One alert per incident: the confirmation alert uses the same key and wins if it came first.
		_, err := tx.Exec(ctx, `INSERT INTO alerts (node_id, severity, source, title, message, dedupe_key)
			VALUES ($1::uuid, 'critical', 'detection', $2, $3, $4)
			ON CONFLICT (dedupe_key) WHERE acknowledged_at IS NULL AND dedupe_key IS NOT NULL DO NOTHING`, nodeID,
			fmt.Sprintf("Eskalation: %s auf %s", p.Category, p.Target),
			fmt.Sprintf("Vorfall %s, Spitze %.0f pps. %s", p.IncidentID, p.PeakPPS, p.Note),
			"incident:"+nodeID+":"+p.IncidentID)
		return err
	case "policy":
		return a.applyPolicyEvent(ctx, tx, nodeID, ev.Action, payload)
	}
	return nil
}

func (a *App) applyIncident(ctx context.Context, tx pgx.Tx, nodeID, action string, payload []byte) error {
	var ev detect.Event
	if err := json.Unmarshal(payload, &ev); err != nil {
		return err
	}
	status := "open"
	var ended *time.Time
	if action == "closed" {
		status = "closed"
		if !ev.Ended.IsZero() {
			t := ev.Ended
			ended = &t
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO incidents (node_id, agent_incident_id, target_prefix, category, verdict, status,
		started_at, ended_at, peak_pps, peak_bps, peak_syn_pps, peak_udp_pps, peak_icmp_pps, confidence, service)
		VALUES ($1::uuid, $2, $3::cidr, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT (node_id, agent_incident_id) DO UPDATE SET
		  category = EXCLUDED.category, verdict = EXCLUDED.verdict, status = EXCLUDED.status,
		  ended_at = COALESCE(EXCLUDED.ended_at, incidents.ended_at),
		  peak_pps = GREATEST(incidents.peak_pps, EXCLUDED.peak_pps),
		  peak_bps = GREATEST(incidents.peak_bps, EXCLUDED.peak_bps),
		  peak_syn_pps = GREATEST(incidents.peak_syn_pps, EXCLUDED.peak_syn_pps),
		  peak_udp_pps = GREATEST(incidents.peak_udp_pps, EXCLUDED.peak_udp_pps),
		  peak_icmp_pps = GREATEST(incidents.peak_icmp_pps, EXCLUDED.peak_icmp_pps),
		  confidence = GREATEST(incidents.confidence, EXCLUDED.confidence),
		  service = EXCLUDED.service,
		  updated_at = now()`,
		nodeID, ev.ID, ev.Target, string(ev.Category), string(ev.Verdict), status, ev.Started, ended,
		ev.PeakPPS, ev.PeakBPS, ev.PeakSYNPPS, ev.PeakUDPPPS, ev.PeakICMPPS, ev.Confidence, ev.Service); err != nil {
		return err
	}
	if ev.Verdict == detect.VerdictConfirmed && action != "closed" {
		_, err := tx.Exec(ctx, `INSERT INTO alerts (node_id, severity, source, title, message, dedupe_key)
			VALUES ($1::uuid, 'critical', 'detection', $2, $3, $4)
			ON CONFLICT (dedupe_key) WHERE acknowledged_at IS NULL AND dedupe_key IS NOT NULL DO NOTHING`, nodeID,
			fmt.Sprintf("Bestätigter Angriff: %s auf %s", ev.Category, ev.Target),
			fmt.Sprintf("Vorfall %s, Spitze %.0f pps, Konfidenz %.2f", ev.ID, ev.PeakPPS, ev.Confidence),
			"incident:"+nodeID+":"+ev.ID)
		return err
	}
	return nil
}

func (a *App) applyMitigation(ctx context.Context, tx pgx.Tx, nodeID, action string, payload []byte) error {
	switch action {
	case "rejected", "approval_expired":
		var p struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(payload, &p)
		if action == "rejected" && p.ID == "" {
			return nil
		}
		var status = "rejected"
		if action == "approval_expired" {
			status = "expired"
			_ = json.Unmarshal(payload, &p)
		}
		id := p.ID
		if id == "" {
			var plan mitigate.Plan
			_ = json.Unmarshal(payload, &plan)
			id = plan.ID
		}
		_, err := tx.Exec(ctx, `UPDATE mitigation_actions SET status = $3, updated_at = now()
			WHERE node_id = $1::uuid AND agent_action_id = $2`, nodeID, id, status)
		return err
	case "apply_failed":
		_, err := tx.Exec(ctx, `INSERT INTO alerts (node_id, severity, source, title, message)
			VALUES ($1::uuid, 'warning', 'mitigation', 'Maßnahme konnte nicht angewendet werden', $2)`, nodeID, string(payload))
		return err
	case "xdp_blocked":
		// Sources blocked in the XDP filter; kept in the audit trail so every block is traceable.
		_, err := tx.Exec(ctx, `INSERT INTO audit_log (actor_type, actor_id, action, target_type, target_id, details)
			VALUES ('node', $1, 'mitigation.xdp_blocked', 'node', $1, $2::jsonb)`, nodeID, string(payload))
		return err
	case "xdp_unavailable":
		_, err := tx.Exec(ctx, `INSERT INTO alerts (node_id, severity, source, title, message, dedupe_key)
			VALUES ($1::uuid, 'warning', 'mitigation', 'XDP-Maßnahme nicht möglich', 'Das Profil verlangt XDP, auf dem Node ist es nicht aktiviert.', $2)
			ON CONFLICT (dedupe_key) WHERE acknowledged_at IS NULL AND dedupe_key IS NOT NULL DO NOTHING`,
			nodeID, "xdp-unavailable:"+nodeID)
		return err
	case "proposed_proposed", "proposed_pending_approval", "proposed_applied", "approved":
		// handled below
	default:
		return nil // unknown actions from newer agents are recorded in agent_events and ignored here
	}
	var plan mitigate.Plan
	if err := json.Unmarshal(payload, &plan); err != nil {
		return err
	}
	status := plan.Status
	switch action {
	case "approved":
		status = mitigate.StatusApplied
	case "proposed_proposed":
		status = mitigate.StatusProposed
	case "proposed_pending_approval":
		status = mitigate.StatusPendingApproval
	case "proposed_applied":
		status = mitigate.StatusApplied
	}
	_, err := tx.Exec(ctx, `INSERT INTO mitigation_actions
		(node_id, agent_action_id, incident_id, kind, target_prefix, rate, auto_block_seconds, status, dry_run, reason)
		VALUES ($1::uuid, $2, (SELECT id FROM incidents WHERE node_id = $1::uuid AND agent_incident_id = $3),
		        $4, $5::cidr, $6, $7, $8, $9, $10)
		ON CONFLICT (node_id, agent_action_id) DO UPDATE SET
		  status = CASE WHEN mitigation_actions.status = 'approved' AND EXCLUDED.status <> 'applied' THEN mitigation_actions.status
		                ELSE EXCLUDED.status END,
		  updated_at = now()`,
		nodeID, plan.ID, plan.IncidentID, plan.Kind, plan.Target, plan.Rate, plan.AutoBlockSeconds, status, plan.DryRun, plan.Reason)
	return err
}

func (a *App) applyPolicyEvent(ctx context.Context, tx pgx.Tx, nodeID, action string, payload []byte) error {
	switch action {
	case "rejected", "apply_failed":
		_, err := tx.Exec(ctx, `INSERT INTO alerts (node_id, severity, source, title, message)
			VALUES ($1::uuid, 'critical', 'policy', $2, $3)`, nodeID,
			"Policy konnte nicht angewendet werden", string(payload))
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log (actor_type, actor_id, action, target_type, target_id, details)
			VALUES ('node', $1, 'policy.' || $2, 'node', $1, $3::jsonb)`, nodeID, action, string(payload))
		return err
	case "applied":
		var p struct {
			Version int64 `json:"version"`
		}
		_ = json.Unmarshal(payload, &p)
		_, err := tx.Exec(ctx, `INSERT INTO audit_log (actor_type, actor_id, action, target_type, target_id, details)
			VALUES ('node', $1, 'policy.applied', 'node', $1, $2::jsonb)`, nodeID, string(payload))
		_ = p
		return err
	}
	return nil
}

// agentPolicy delivers the signed envelope of the node's desired policy version.
func (a *App) agentPolicy(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := a.authenticateAgent(w, r, nil)
	if !ok {
		return
	}
	var env policy.Envelope
	err := a.db.QueryRow(r.Context(), `SELECT pv.version, pv.body, pv.sha256, pv.signature
		FROM nodes n JOIN policy_versions pv ON pv.node_id = n.id AND pv.version = n.desired_policy_version
		WHERE n.id = $1::uuid`, nodeID).Scan(&env.Version, &env.Body, &env.SHA256, &env.Signature)
	if errors.Is(err, pgx.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "keine policy vorhanden")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	writeJSON(w, http.StatusOK, env)
}

// normalizeKeyIDs keeps only plausible key IDs (16 hex characters), at most four.
func normalizeKeyIDs(in []string) []string {
	out := []string{}
	for _, id := range in {
		if len(id) != 16 || len(out) >= 4 {
			continue
		}
		ok := true
		for _, c := range id {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				ok = false
			}
		}
		if ok {
			out = append(out, id)
		}
	}
	return out
}
