package panel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// freshness bounds which samples count as "live". Older samples are never shown as current.
const freshness = 2 * time.Minute

var seriesRanges = map[string]struct {
	span   time.Duration
	bucket string
}{
	"1h":  {time.Hour, "1 minute"},
	"6h":  {6 * time.Hour, "5 minutes"},
	"24h": {24 * time.Hour, "15 minutes"},
	"7d":  {7 * 24 * time.Hour, "1 hour"},
}

// Dashboard is the summary shown on the start page. Every number comes from stored
// measurements; a node or target without a fresh sample contributes nothing.
type Dashboard struct {
	GeneratedAt      time.Time      `json:"generated_at"`
	Nodes            map[string]int `json:"nodes"`
	ProtectedTargets int            `json:"protected_targets"`
	ThroughputGbps   float64        `json:"throughput_gbps"`
	PPS              float64        `json:"pps"`
	DroppedPPS       float64        `json:"dropped_pps"`
	OpenIncidents    int            `json:"open_incidents"`
	ConfirmedOpen    int            `json:"confirmed_open"`
	Incidents24h     int            `json:"incidents_24h"`
	ActiveMitigation int            `json:"active_mitigations"`
	PendingApprovals int            `json:"pending_approvals"`
	ActiveBlocks     int            `json:"active_blocks"`
	UnackedAlerts    int            `json:"unacked_alerts"`
	NodeDetails      []nodeLive     `json:"node_details"`
	TargetDetails    []targetLive   `json:"target_details"`
}

type nodeLive struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Status     string     `json:"status"`
	CPUPercent *float64   `json:"cpu_percent"`
	MemPercent *float64   `json:"mem_percent"`
	Gbps       *float64   `json:"gbps"`
	PPS        *float64   `json:"pps"`
	SampledAt  *time.Time `json:"sampled_at"`
	AppliedVer int64      `json:"applied_policy_version"`
	DesiredVer int64      `json:"desired_policy_version"`
	SyncStatus string     `json:"sync_status"`
}

type targetLive struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	NodeName   string     `json:"node_name"`
	Gbps       *float64   `json:"gbps"`
	PPS        *float64   `json:"pps"`
	SYNPPS     *float64   `json:"syn_pps"`
	DroppedPPS *float64   `json:"dropped_pps"`
	SampledAt  *time.Time `json:"sampled_at"`
}

func (a *App) dashboard(w http.ResponseWriter, r *http.Request, _ Actor) {
	ctx := r.Context()
	d := Dashboard{GeneratedAt: a.now(), Nodes: map[string]int{}}
	fresh := a.now().Add(-freshness)

	rows, err := a.db.Query(ctx, `
		SELECT n.id::text, n.name, n.status, n.applied_policy_version, n.desired_policy_version, n.sync_status,
		       m.cpu_percent, m.mem_used_percent, (m.rx_bps + m.tx_bps) / 1e9, m.rx_pps + m.tx_pps, m.ts
		FROM nodes n
		LEFT JOIN LATERAL (SELECT * FROM node_metrics nm WHERE nm.node_id = n.id ORDER BY ts DESC LIMIT 1) m ON true
		WHERE n.status <> 'revoked'
		ORDER BY n.name`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "abfrage fehlgeschlagen")
		return
	}
	for rows.Next() {
		var n nodeLive
		if err := rows.Scan(&n.ID, &n.Name, &n.Status, &n.AppliedVer, &n.DesiredVer, &n.SyncStatus,
			&n.CPUPercent, &n.MemPercent, &n.Gbps, &n.PPS, &n.SampledAt); err != nil {
			rows.Close()
			writeErr(w, http.StatusInternalServerError, "lesefehler")
			return
		}
		d.Nodes[n.Status]++
		if n.SampledAt != nil && n.SampledAt.Before(fresh) {
			n.CPUPercent, n.MemPercent, n.Gbps, n.PPS = nil, nil, nil, nil
		} else if n.SampledAt != nil && n.Gbps != nil {
			d.ThroughputGbps += *n.Gbps
			d.PPS += *n.PPS
		}
		d.NodeDetails = append(d.NodeDetails, n)
	}
	rows.Close()

	rows, err = a.db.Query(ctx, `
		SELECT t.id::text, t.name, t.prefix::text, n.name,
		       (m.bps) / 1e9, m.pps, m.syn_pps, m.dropped_pps, m.ts
		FROM protected_targets t
		JOIN nodes n ON n.id = t.node_id
		LEFT JOIN LATERAL (SELECT * FROM target_metrics tm WHERE tm.target_id = t.id ORDER BY ts DESC LIMIT 1) m ON true
		ORDER BY t.prefix`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "abfrage fehlgeschlagen")
		return
	}
	for rows.Next() {
		var t targetLive
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &t.NodeName, &t.Gbps, &t.PPS, &t.SYNPPS, &t.DroppedPPS, &t.SampledAt); err != nil {
			rows.Close()
			writeErr(w, http.StatusInternalServerError, "lesefehler")
			return
		}
		d.ProtectedTargets++
		if t.SampledAt != nil && t.SampledAt.Before(fresh) {
			t.Gbps, t.PPS, t.SYNPPS, t.DroppedPPS = nil, nil, nil, nil
		} else if t.SampledAt != nil {
			d.DroppedPPS += derefOr(t.DroppedPPS)
		}
		d.TargetDetails = append(d.TargetDetails, t)
	}
	rows.Close()

	counts := []struct {
		dst *int
		sql string
	}{
		{&d.OpenIncidents, `SELECT count(*) FROM incidents WHERE status = 'open'`},
		{&d.ConfirmedOpen, `SELECT count(*) FROM incidents WHERE status = 'open' AND verdict = 'confirmed_attack'`},
		{&d.Incidents24h, `SELECT count(*) FROM incidents WHERE started_at > now() - interval '24 hours'`},
		{&d.ActiveMitigation, `SELECT count(*) FROM mitigation_actions WHERE status = 'applied' AND NOT dry_run`},
		{&d.PendingApprovals, `SELECT count(*) FROM mitigation_actions WHERE status = 'pending_approval'`},
		{&d.ActiveBlocks, `SELECT count(*) FROM rules WHERE kind = 'deny' AND revoked_at IS NULL AND expires_at > now()`},
		{&d.UnackedAlerts, `SELECT count(*) FROM alerts WHERE acknowledged_at IS NULL`},
	}
	for _, c := range counts {
		if err := a.db.QueryRow(ctx, c.sql).Scan(c.dst); err != nil {
			writeErr(w, http.StatusInternalServerError, "abfrage fehlgeschlagen")
			return
		}
	}
	writeJSON(w, http.StatusOK, d)
}

func derefOr(v *float64) float64 {
	if v == nil {
		return 0
	}
	return *v
}

type seriesPoint struct {
	TS   time.Time `json:"ts"`
	Gbps *float64  `json:"gbps,omitempty"`
	PPS  *float64  `json:"pps,omitempty"`
	CPU  *float64  `json:"cpu_percent,omitempty"`
	Mem  *float64  `json:"mem_percent,omitempty"`
	SYN  *float64  `json:"syn_pps,omitempty"`
	Drop *float64  `json:"dropped_pps,omitempty"`
}

func rangeOf(r *http.Request) (time.Time, string, error) {
	key := r.URL.Query().Get("range")
	if key == "" {
		key = "1h"
	}
	spec, ok := seriesRanges[key]
	if !ok {
		return time.Time{}, "", fmt.Errorf("range muss 1h, 6h, 24h oder 7d sein")
	}
	return time.Now().Add(-spec.span), spec.bucket, nil
}

func (a *App) nodeSeries(w http.ResponseWriter, r *http.Request, _ Actor) {
	since, bucket, err := rangeOf(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rows, err := a.db.Query(r.Context(), `
		SELECT date_bin($3::interval, ts, timestamp 'epoch') AS b,
		       avg((rx_bps + tx_bps) / 1e9), avg(rx_pps + tx_pps), avg(cpu_percent), avg(mem_used_percent)
		FROM node_metrics WHERE node_id = $1::uuid AND ts >= $2
		GROUP BY b ORDER BY b`, r.PathValue("id"), since, bucket)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "abfrage fehlgeschlagen")
		return
	}
	defer rows.Close()
	out := []seriesPoint{}
	for rows.Next() {
		var p seriesPoint
		if err := rows.Scan(&p.TS, &p.Gbps, &p.PPS, &p.CPU, &p.Mem); err != nil {
			writeErr(w, http.StatusInternalServerError, "lesefehler")
			return
		}
		out = append(out, p)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) targetSeries(w http.ResponseWriter, r *http.Request, _ Actor) {
	since, bucket, err := rangeOf(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rows, err := a.db.Query(r.Context(), `
		SELECT date_bin($3::interval, ts, timestamp 'epoch') AS b,
		       avg(bps / 1e9), avg(pps), avg(syn_pps), avg(dropped_pps)
		FROM target_metrics WHERE target_id = $1::uuid AND ts >= $2
		GROUP BY b ORDER BY b`, r.PathValue("id"), since, bucket)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "abfrage fehlgeschlagen")
		return
	}
	defer rows.Close()
	out := []seriesPoint{}
	for rows.Next() {
		var p seriesPoint
		if err := rows.Scan(&p.TS, &p.Gbps, &p.PPS, &p.SYN, &p.Drop); err != nil {
			writeErr(w, http.StatusInternalServerError, "lesefehler")
			return
		}
		out = append(out, p)
	}
	writeJSON(w, http.StatusOK, out)
}

type incidentDTO struct {
	ID         string     `json:"id"`
	NodeName   string     `json:"node_name"`
	Target     string     `json:"target"`
	Category   string     `json:"category"`
	Verdict    string     `json:"verdict"`
	Status     string     `json:"status"`
	StartedAt  time.Time  `json:"started_at"`
	EndedAt    *time.Time `json:"ended_at"`
	PeakPPS    float64    `json:"peak_pps"`
	PeakBPS    float64    `json:"peak_bps"`
	PeakSYNPPS float64    `json:"peak_syn_pps"`
	PeakUDPPPS float64    `json:"peak_udp_pps"`
	PeakICMPPS float64    `json:"peak_icmp_pps"`
	Confidence float64    `json:"confidence"`
}

const incidentSelect = `SELECT i.id::text, n.name, i.target_prefix::text, i.category, i.verdict, i.status,
	i.started_at, i.ended_at, i.peak_pps, i.peak_bps, i.peak_syn_pps, i.peak_udp_pps, i.peak_icmp_pps, i.confidence
	FROM incidents i JOIN nodes n ON n.id = i.node_id`

func scanIncident(row rowScanner) (incidentDTO, error) {
	var d incidentDTO
	err := row.Scan(&d.ID, &d.NodeName, &d.Target, &d.Category, &d.Verdict, &d.Status, &d.StartedAt, &d.EndedAt,
		&d.PeakPPS, &d.PeakBPS, &d.PeakSYNPPS, &d.PeakUDPPPS, &d.PeakICMPPS, &d.Confidence)
	return d, err
}

func (a *App) listIncidents(w http.ResponseWriter, r *http.Request, _ Actor) {
	q := incidentSelect + ` WHERE 1=1`
	switch r.URL.Query().Get("status") {
	case "open":
		q += ` AND i.status = 'open'`
	case "closed":
		q += ` AND i.status = 'closed'`
	}
	if v := r.URL.Query().Get("node_id"); v != "" {
		q += fmt.Sprintf(` AND i.node_id = '%s'::uuid`, sanitizeUUID(v))
	}
	limit := 100
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 500 {
		limit = n
	}
	q += fmt.Sprintf(` ORDER BY i.started_at DESC LIMIT %d`, limit)
	rows, err := a.db.Query(r.Context(), q)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "filter ungültig")
		return
	}
	defer rows.Close()
	out := []incidentDTO{}
	for rows.Next() {
		d, err := scanIncident(rows)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "lesefehler")
			return
		}
		out = append(out, d)
	}
	writeJSON(w, http.StatusOK, out)
}

// sanitizeUUID returns the input only if it is a canonical UUID. Anything else becomes
// an impossible value, so it can never be used to inject SQL.
func sanitizeUUID(s string) string {
	if len(s) != 36 {
		return "00000000-0000-0000-0000-000000000000"
	}
	for i, c := range s {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return "00000000-0000-0000-0000-000000000000"
			}
		case (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'):
		default:
			return "00000000-0000-0000-0000-000000000000"
		}
	}
	return s
}

func (a *App) getIncident(w http.ResponseWriter, r *http.Request, _ Actor) {
	ctx := r.Context()
	d, err := scanIncident(a.db.QueryRow(ctx, incidentSelect+` WHERE i.id = $1::uuid`, r.PathValue("id")))
	if err != nil {
		writeErr(w, http.StatusNotFound, "vorfall nicht gefunden")
		return
	}

	type tlEvent struct {
		TS      time.Time       `json:"ts"`
		Action  string          `json:"action"`
		Payload json.RawMessage `json:"payload"`
	}
	timeline := []tlEvent{}
	rows, err := a.db.Query(ctx, `
		SELECT e.ts, e.action, e.payload::text FROM agent_events e
		JOIN incidents i ON i.node_id = e.node_id AND e.payload->>'id' = i.agent_incident_id
		WHERE i.id = $1::uuid AND e.type = 'incident' ORDER BY e.ts`, r.PathValue("id"))
	if err == nil {
		for rows.Next() {
			var e tlEvent
			var p string
			if rows.Scan(&e.TS, &e.Action, &p) == nil {
				e.Payload = json.RawMessage(p)
				timeline = append(timeline, e)
			}
		}
		rows.Close()
	}

	type point struct {
		TS   time.Time `json:"ts"`
		PPS  float64   `json:"pps"`
		SYN  float64   `json:"syn_pps"`
		UDP  float64   `json:"udp_pps"`
		Gbps float64   `json:"gbps"`
	}
	series := []point{}
	end := a.now()
	if d.EndedAt != nil {
		end = d.EndedAt.Add(time.Minute)
	}
	rows, err = a.db.Query(ctx, `
		SELECT tm.ts, tm.pps, tm.syn_pps, tm.udp_pps, tm.bps / 1e9 FROM target_metrics tm
		JOIN protected_targets t ON t.id = tm.target_id
		JOIN incidents i ON i.node_id = t.node_id AND i.target_prefix = t.prefix
		WHERE i.id = $1::uuid AND tm.ts BETWEEN $2 - interval '1 minute' AND $3
		ORDER BY tm.ts LIMIT 2000`, r.PathValue("id"), d.StartedAt, end)
	if err == nil {
		for rows.Next() {
			var p point
			if rows.Scan(&p.TS, &p.PPS, &p.SYN, &p.UDP, &p.Gbps) == nil {
				series = append(series, p)
			}
		}
		rows.Close()
	}

	actions := []map[string]any{}
	rows, err = a.db.Query(ctx, `SELECT id::text, kind, status, dry_run, rate, auto_block_seconds, reason, created_at, decided_at
		FROM mitigation_actions WHERE incident_id = $1::uuid ORDER BY created_at`, r.PathValue("id"))
	if err == nil {
		for rows.Next() {
			var id, kind, status, reason string
			var dry bool
			var rate, block int
			var created time.Time
			var decided *time.Time
			if rows.Scan(&id, &kind, &status, &dry, &rate, &block, &reason, &created, &decided) == nil {
				actions = append(actions, map[string]any{"id": id, "kind": kind, "status": status, "dry_run": dry,
					"rate": rate, "auto_block_seconds": block, "reason": reason, "created_at": created, "decided_at": decided})
			}
		}
		rows.Close()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"incident": d, "timeline": timeline, "target_series": series, "actions": actions,
		"classification_note": "bestätigt = Schwellwert über Haltezeit; verdächtig = Anomalie ohne absolute Schwelle oder kurze Überschreitung; spitze = normaler Lastanstieg",
	})
}

type actionDTO struct {
	ID               string     `json:"id"`
	NodeName         string     `json:"node_name"`
	Kind             string     `json:"kind"`
	Target           string     `json:"target"`
	Rate             int        `json:"rate"`
	AutoBlockSeconds int        `json:"auto_block_seconds"`
	Status           string     `json:"status"`
	DryRun           bool       `json:"dry_run"`
	Reason           string     `json:"reason"`
	CreatedAt        time.Time  `json:"created_at"`
	DecidedAt        *time.Time `json:"decided_at"`
	DecidedBy        *string    `json:"decided_by"`
}

func (a *App) listActions(w http.ResponseWriter, r *http.Request, _ Actor) {
	rows, err := a.db.Query(r.Context(), `SELECT m.id::text, n.name, m.kind, m.target_prefix::text, m.rate, m.auto_block_seconds,
		m.status, m.dry_run, m.reason, m.created_at, m.decided_at, u.email
		FROM mitigation_actions m JOIN nodes n ON n.id = m.node_id LEFT JOIN users u ON u.id = m.decided_by
		ORDER BY m.created_at DESC LIMIT 200`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "abfrage fehlgeschlagen")
		return
	}
	defer rows.Close()
	out := []actionDTO{}
	for rows.Next() {
		var d actionDTO
		if err := rows.Scan(&d.ID, &d.NodeName, &d.Kind, &d.Target, &d.Rate, &d.AutoBlockSeconds, &d.Status, &d.DryRun,
			&d.Reason, &d.CreatedAt, &d.DecidedAt, &d.DecidedBy); err != nil {
			writeErr(w, http.StatusInternalServerError, "lesefehler")
			return
		}
		out = append(out, d)
	}
	writeJSON(w, http.StatusOK, out)
}

// decideAction approves or rejects a pending mitigation. The agent learns the decision
// with its next heartbeat; an approval that is never delivered expires on the agent.
func (a *App) decideAction(decision string) actorHandler {
	return func(w http.ResponseWriter, r *http.Request, actor Actor) {
		ctx := r.Context()
		tag, err := a.db.Exec(ctx, `UPDATE mitigation_actions SET status = $2, decided_by = $3::uuid, decided_at = now(), updated_at = now()
			WHERE id = $1::uuid AND status = 'pending_approval'`, r.PathValue("id"), decision, actor.UserID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "interner Fehler")
			return
		}
		if tag.RowsAffected() == 0 {
			writeErr(w, http.StatusConflict, "maßnahme wartet nicht auf freigabe (oder existiert nicht)")
			return
		}
		a.audit(ctx, a.db, "user", actor.UserID, "action."+decision, "mitigation", r.PathValue("id"), nil, ipString(r))
		writeJSON(w, http.StatusOK, map[string]string{"status": decision})
	}
}

func (a *App) listAlerts(w http.ResponseWriter, r *http.Request, _ Actor) {
	q := `SELECT al.id::text, al.node_id::text, al.severity, al.source, al.title, al.message, al.created_at, al.acknowledged_at
		FROM alerts al`
	if r.URL.Query().Get("open") != "false" {
		q += ` WHERE al.acknowledged_at IS NULL`
	}
	q += ` ORDER BY al.created_at DESC LIMIT 200`
	rows, err := a.db.Query(r.Context(), q)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "abfrage fehlgeschlagen")
		return
	}
	defer rows.Close()
	type alertDTO struct {
		ID        string     `json:"id"`
		NodeID    *string    `json:"node_id"`
		Severity  string     `json:"severity"`
		Source    string     `json:"source"`
		Title     string     `json:"title"`
		Message   string     `json:"message"`
		CreatedAt time.Time  `json:"created_at"`
		AckedAt   *time.Time `json:"acknowledged_at"`
	}
	out := []alertDTO{}
	for rows.Next() {
		var d alertDTO
		if err := rows.Scan(&d.ID, &d.NodeID, &d.Severity, &d.Source, &d.Title, &d.Message, &d.CreatedAt, &d.AckedAt); err != nil {
			writeErr(w, http.StatusInternalServerError, "lesefehler")
			return
		}
		out = append(out, d)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) ackAlert(w http.ResponseWriter, r *http.Request, actor Actor) {
	tag, err := a.db.Exec(r.Context(), `UPDATE alerts SET acknowledged_at = now(), acknowledged_by = $2::uuid
		WHERE id = $1::uuid AND acknowledged_at IS NULL`, r.PathValue("id"), actor.UserID)
	if err != nil || tag.RowsAffected() == 0 {
		writeErr(w, http.StatusNotFound, "offener alarm nicht gefunden")
		return
	}
	a.audit(r.Context(), a.db, "user", actor.UserID, "alert.ack", "alert", r.PathValue("id"), nil, ipString(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "bestätigt"})
}

func (a *App) listAudit(w http.ResponseWriter, r *http.Request, _ Actor) {
	limit := 100
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 500 {
		limit = n
	}
	rows, err := a.db.Query(r.Context(), `SELECT id, ts, actor_type, actor_id, action, COALESCE(target_type,''), COALESCE(target_id,''),
		details::text FROM audit_log ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "abfrage fehlgeschlagen")
		return
	}
	defer rows.Close()
	type entry struct {
		ID         int64           `json:"id"`
		TS         time.Time       `json:"ts"`
		ActorType  string          `json:"actor_type"`
		ActorID    string          `json:"actor_id"`
		Action     string          `json:"action"`
		TargetType string          `json:"target_type"`
		TargetID   string          `json:"target_id"`
		Details    json.RawMessage `json:"details"`
	}
	out := []entry{}
	for rows.Next() {
		var e entry
		var d string
		if err := rows.Scan(&e.ID, &e.TS, &e.ActorType, &e.ActorID, &e.Action, &e.TargetType, &e.TargetID, &d); err != nil {
			writeErr(w, http.StatusInternalServerError, "lesefehler")
			return
		}
		e.Details = json.RawMessage(d)
		out = append(out, e)
	}
	writeJSON(w, http.StatusOK, out)
}
