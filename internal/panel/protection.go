package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/vaktikos/ddos-prot/internal/netaddr"
	"github.com/vaktikos/ddos-prot/internal/policy"
)

// Limits applied to every compiled policy. They bound what one node may do at once.
const (
	maxActiveBlocks   = 1000
	maxDynamicEntries = 4096
)

// querier is satisfied by *pgxpool.Pool and pgx.Tx.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// lockNode takes the node row lock. Every mutating transaction calls it before any
// other write: inserts that reference nodes take a shared lock, and upgrading that
// later while another transaction holds it causes a deadlock under concurrency.
func lockNode(ctx context.Context, q querier, nodeID string) error {
	var one int
	return q.QueryRow(ctx, `SELECT 1 FROM nodes WHERE id = $1::uuid FOR UPDATE`, nodeID).Scan(&one)
}

// compilePolicy builds the complete desired state of a node from the database.
// Nothing is stored here; the caller decides whether to sign and publish it.
func (a *App) compilePolicy(ctx context.Context, q querier, nodeID string, version int64) (*policy.Policy, []string, error) {
	var mode string
	var cidrsJSON string
	var status string
	err := q.QueryRow(ctx, `SELECT mode, status, COALESCE(array_to_json(management_cidrs)::text, '[]') FROM nodes WHERE id = $1::uuid`,
		nodeID).Scan(&mode, &status, &cidrsJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("node nicht gefunden")
	}
	if status == "revoked" {
		return nil, nil, errors.New("node ist widerrufen")
	}
	var cidrs []string
	if err := json.Unmarshal([]byte(cidrsJSON), &cidrs); err != nil {
		return nil, nil, err
	}

	p := &policy.Policy{
		Version: version, NodeID: nodeID, Mode: mode, IssuedAt: time.Now().UTC(),
		Profiles: map[string]policy.Profile{},
		Limits:   policy.Limits{MaxActiveBlocks: maxActiveBlocks, MaxDynamicEntries: maxDynamicEntries},
	}

	rows, err := q.Query(ctx, `
		SELECT t.name, t.prefix::text, pr.name, pr.config::text,
		       COALESCE(json_agg(json_build_object('name', s.name, 'protocol', s.protocol, 'port', s.port)
		                ORDER BY s.protocol, s.port) FILTER (WHERE s.id IS NOT NULL), '[]')::text
		FROM protected_targets t
		JOIN protection_profiles pr ON pr.id = t.profile_id
		LEFT JOIN services s ON s.target_id = t.id
		WHERE t.node_id = $1::uuid
		GROUP BY t.id, t.name, t.prefix, pr.name, pr.config
		ORDER BY t.prefix`, nodeID)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var t policy.Target
		var profName, profConfig, services string
		if err := rows.Scan(&t.Name, &t.Prefix, &profName, &profConfig, &services); err != nil {
			rows.Close()
			return nil, nil, err
		}
		if err := json.Unmarshal([]byte(services), &t.Services); err != nil {
			rows.Close()
			return nil, nil, err
		}
		var prof policy.Profile
		if err := json.Unmarshal([]byte(profConfig), &prof); err != nil {
			rows.Close()
			return nil, nil, err
		}
		t.Profile = profName
		p.Profiles[profName] = prof
		p.Targets = append(p.Targets, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	rules, err := q.Query(ctx, `
		SELECT id::text, kind, prefix::text, reason, expires_at
		FROM rules
		WHERE node_id = $1::uuid AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())
		ORDER BY prefix`, nodeID)
	if err != nil {
		return nil, nil, err
	}
	for rules.Next() {
		var id, kind, prefix, reason string
		var expires *time.Time
		if err := rules.Scan(&id, &kind, &prefix, &reason, &expires); err != nil {
			rules.Close()
			return nil, nil, err
		}
		if kind == "allow" {
			p.Trusted = append(p.Trusted, prefix)
			continue
		}
		if expires == nil {
			rules.Close()
			return nil, nil, errors.New("deny-regel ohne Ablaufzeit in der Datenbank")
		}
		p.Blocks = append(p.Blocks, policy.ManualBlock{RuleID: id, Prefix: prefix, Reason: reason, ExpiresAt: expires.UTC()})
	}
	rules.Close()
	if err := rules.Err(); err != nil {
		return nil, nil, err
	}
	return p, cidrs, nil
}

// publishPolicy compiles, validates, signs and stores the next version of a node's
// policy inside the caller's transaction. Any validation failure aborts the change.
func (a *App) publishPolicy(ctx context.Context, q querier, nodeID, note, actorID string) error {
	if err := lockNode(ctx, q, nodeID); err != nil {
		return err
	}
	var next int64
	if err := q.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) + 1 FROM policy_versions WHERE node_id = $1::uuid`, nodeID).Scan(&next); err != nil {
		return err
	}
	p, cidrs, err := a.compilePolicy(ctx, q, nodeID, next)
	if err != nil {
		return err
	}
	return a.storePolicy(ctx, q, nodeID, p, cidrs, note, actorID)
}

func (a *App) storePolicy(ctx context.Context, q querier, nodeID string, p *policy.Policy, cidrs []string, note, actorID string) error {
	mgmt := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		pre, err := netaddr.ParsePrefix(c)
		if err != nil {
			return err
		}
		mgmt = append(mgmt, pre)
	}
	if err := policy.Validate(p, mgmt); err != nil {
		return err
	}
	env, err := policy.SignWith(a.sg, a.sg.Public(), p)
	if err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `INSERT INTO policy_versions (node_id, version, body, sha256, signature, note, created_by)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)`, nodeID, p.Version, env.Body, env.SHA256, env.Signature, note, actorID); err != nil {
		return err
	}
	_, err = q.Exec(ctx, `UPDATE nodes SET desired_policy_version = $2, sync_status = 'pending', sync_error = '', updated_at = now()
		WHERE id = $1::uuid`, nodeID, p.Version)
	return err
}

// --- Targets -----------------------------------------------------------------------

type serviceDTO struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

type targetDTO struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	Prefix     string       `json:"prefix"`
	Profile    string       `json:"profile"`
	Services   []serviceDTO `json:"services"`
	PPS        *float64     `json:"pps"`
	BPS        *float64     `json:"bps"`
	SYNPPS     *float64     `json:"syn_pps"`
	DroppedPPS *float64     `json:"dropped_pps"`
	MeasuredAt *time.Time   `json:"measured_at"`
}

func (a *App) listTargets(w http.ResponseWriter, r *http.Request, _ Actor) {
	rows, err := a.db.Query(r.Context(), `
		SELECT t.id::text, t.name, t.prefix::text, pr.name,
		       COALESCE(json_agg(json_build_object('name', s.name, 'protocol', s.protocol, 'port', s.port)
		                ORDER BY s.protocol, s.port) FILTER (WHERE s.id IS NOT NULL), '[]')::text,
		       m.pps, m.bps, m.syn_pps, m.dropped_pps, m.ts
		FROM protected_targets t
		JOIN protection_profiles pr ON pr.id = t.profile_id
		LEFT JOIN services s ON s.target_id = t.id
		LEFT JOIN LATERAL (
		    SELECT pps, bps, syn_pps, dropped_pps, ts FROM target_metrics tm
		    WHERE tm.target_id = t.id ORDER BY ts DESC LIMIT 1) m ON true
		WHERE t.node_id = $1::uuid
		GROUP BY t.id, t.name, t.prefix, pr.name, m.pps, m.bps, m.syn_pps, m.dropped_pps, m.ts
		ORDER BY t.prefix`, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "abfrage fehlgeschlagen")
		return
	}
	defer rows.Close()
	out := []targetDTO{}
	for rows.Next() {
		var t targetDTO
		var svc string
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &t.Profile, &svc, &t.PPS, &t.BPS, &t.SYNPPS, &t.DroppedPPS, &t.MeasuredAt); err != nil {
			writeErr(w, http.StatusInternalServerError, "lesefehler")
			return
		}
		if err := json.Unmarshal([]byte(svc), &t.Services); err != nil {
			writeErr(w, http.StatusInternalServerError, "lesefehler")
			return
		}
		out = append(out, t)
	}
	writeJSON(w, http.StatusOK, out)
}

type createTargetRequest struct {
	Name     string       `json:"name"`
	Prefix   string       `json:"prefix"`
	Profile  string       `json:"profile"`
	Services []serviceDTO `json:"services"`
}

func (a *App) createTarget(w http.ResponseWriter, r *http.Request, actor Actor) {
	var req createTargetRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	pre, err := netaddr.ParsePrefix(req.Prefix)
	if err == nil {
		err = netaddr.ValidateProtected(pre)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 100 {
		writeErr(w, http.StatusBadRequest, "name ist erforderlich (max. 100 Zeichen)")
		return
	}
	seen := map[string]bool{}
	for i, s := range req.Services {
		if s.Protocol != policy.ProtoTCP && s.Protocol != policy.ProtoUDP {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("dienst %d: protokoll muss tcp oder udp sein", i))
			return
		}
		if _, err := netaddr.ParsePort(s.Port); err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("dienst %d: %v", i, err))
			return
		}
		k := fmt.Sprintf("%s/%d", s.Protocol, s.Port)
		if seen[k] {
			writeErr(w, http.StatusBadRequest, "doppelter dienst "+k)
			return
		}
		seen[k] = true
	}
	ctx := r.Context()
	nodeID := r.PathValue("id")
	tx, err := a.db.Begin(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	defer tx.Rollback(ctx)
	if err := lockNode(ctx, tx, nodeID); err != nil {
		writeErr(w, http.StatusNotFound, "node nicht gefunden")
		return
	}
	var targetID string
	err = tx.QueryRow(ctx, `INSERT INTO protected_targets (node_id, name, prefix, profile_id)
		SELECT $1::uuid, $2, $3::cidr, id FROM protection_profiles WHERE name = $4
		RETURNING id::text`, nodeID, req.Name, pre.String(), req.Profile).Scan(&targetID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeErr(w, http.StatusBadRequest, "profil nicht gefunden")
		return
	}
	if err != nil {
		writeErr(w, http.StatusConflict, "ziel existiert bereits für diesen node")
		return
	}
	for _, s := range req.Services {
		if _, err := tx.Exec(ctx, `INSERT INTO services (target_id, name, protocol, port) VALUES ($1::uuid, $2, $3, $4)`,
			targetID, s.Name, s.Protocol, s.Port); err != nil {
			writeErr(w, http.StatusInternalServerError, "dienst konnte nicht gespeichert werden")
			return
		}
	}
	if err := a.publishPolicy(ctx, tx, nodeID, "Ziel "+pre.String()+" hinzugefügt", actor.UserID); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "policy abgelehnt: "+err.Error())
		return
	}
	a.audit(ctx, tx, "user", actor.UserID, "target.create", "target", targetID,
		map[string]any{"prefix": pre.String(), "node_id": nodeID, "services": len(req.Services)}, ipString(r))
	if err := tx.Commit(ctx); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": targetID, "prefix": pre.String()})
}

func (a *App) deleteTarget(w http.ResponseWriter, r *http.Request, actor Actor) {
	ctx := r.Context()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	defer tx.Rollback(ctx)
	var nodeID, prefix string
	if err := tx.QueryRow(ctx, `SELECT node_id::text, prefix::text FROM protected_targets WHERE id = $1::uuid`,
		r.PathValue("id")).Scan(&nodeID, &prefix); err != nil {
		writeErr(w, http.StatusNotFound, "ziel nicht gefunden")
		return
	}
	if err := lockNode(ctx, tx, nodeID); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	if _, err := tx.Exec(ctx, `DELETE FROM protected_targets WHERE id = $1::uuid`, r.PathValue("id")); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	if err := a.publishPolicy(ctx, tx, nodeID, "Ziel "+prefix+" entfernt", actor.UserID); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "policy abgelehnt: "+err.Error())
		return
	}
	a.audit(ctx, tx, "user", actor.UserID, "target.delete", "target", r.PathValue("id"), map[string]any{"prefix": prefix}, ipString(r))
	if err := tx.Commit(ctx); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "entfernt"})
}

// --- Rules ---------------------------------------------------------------------------

type ruleDTO struct {
	ID        string     `json:"id"`
	NodeID    string     `json:"node_id"`
	Kind      string     `json:"kind"`
	Prefix    string     `json:"prefix"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at"`
}

func (a *App) listRules(w http.ResponseWriter, r *http.Request, _ Actor) {
	onlyActive := r.URL.Query().Get("active") != "false"
	q := `SELECT id::text, node_id::text, kind, prefix::text, reason, expires_at, created_at, revoked_at
		FROM rules WHERE node_id = $1::uuid`
	if onlyActive {
		q += ` AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`
	}
	q += ` ORDER BY created_at DESC LIMIT 500`
	rows, err := a.db.Query(r.Context(), q, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "abfrage fehlgeschlagen")
		return
	}
	defer rows.Close()
	out := []ruleDTO{}
	for rows.Next() {
		var rd ruleDTO
		if err := rows.Scan(&rd.ID, &rd.NodeID, &rd.Kind, &rd.Prefix, &rd.Reason, &rd.ExpiresAt, &rd.CreatedAt, &rd.RevokedAt); err != nil {
			writeErr(w, http.StatusInternalServerError, "lesefehler")
			return
		}
		out = append(out, rd)
	}
	writeJSON(w, http.StatusOK, out)
}

type createRuleRequest struct {
	Kind      string     `json:"kind"`
	Prefix    string     `json:"prefix"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at"`
}

func (a *App) createRule(w http.ResponseWriter, r *http.Request, actor Actor) {
	var req createRuleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	pre, err := netaddr.ParsePrefix(req.Prefix)
	if err == nil {
		err = netaddr.ValidateProtected(pre)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if len(req.Reason) < 3 || len(req.Reason) > 500 {
		writeErr(w, http.StatusBadRequest, "begründung ist erforderlich (3 bis 500 Zeichen)")
		return
	}
	now := time.Now()
	switch req.Kind {
	case "allow":
		if req.ExpiresAt != nil && !req.ExpiresAt.After(now) {
			writeErr(w, http.StatusBadRequest, "ablaufzeit liegt in der Vergangenheit")
			return
		}
	case "deny":
		if req.ExpiresAt == nil {
			writeErr(w, http.StatusBadRequest, "sperren sind immer zeitlich begrenzt: expires_at angeben")
			return
		}
		if !req.ExpiresAt.After(now.Add(time.Minute)) || req.ExpiresAt.After(now.Add(policy.MaxBlockDays*24*time.Hour)) {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("sperre muss zwischen 1 Minute und %d Tagen laufen", policy.MaxBlockDays))
			return
		}
	default:
		writeErr(w, http.StatusBadRequest, "kind muss allow oder deny sein")
		return
	}

	ctx := r.Context()
	nodeID := r.PathValue("id")
	tx, err := a.db.Begin(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	defer tx.Rollback(ctx)
	if err := lockNode(ctx, tx, nodeID); err != nil {
		writeErr(w, http.StatusNotFound, "node nicht gefunden")
		return
	}
	var ruleID string
	err = tx.QueryRow(ctx, `INSERT INTO rules (node_id, kind, prefix, reason, expires_at, created_by)
		VALUES ($1::uuid, $2, $3::cidr, $4, $5, $6::uuid) RETURNING id::text`,
		nodeID, req.Kind, pre.String(), req.Reason, req.ExpiresAt, actor.UserID).Scan(&ruleID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "regel ungültig (node unbekannt?)")
		return
	}
	if _, err := tx.Exec(ctx, `INSERT INTO rule_events (rule_id, action, actor_id, details) VALUES ($1::uuid, 'created', $2, $3::jsonb)`,
		ruleID, actor.UserID, mustJSON(map[string]any{"kind": req.Kind, "prefix": pre.String(), "reason": req.Reason})); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	if err := a.publishPolicy(ctx, tx, nodeID, fmt.Sprintf("%s %s", req.Kind, pre), actor.UserID); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "regel abgelehnt: "+err.Error())
		return
	}
	a.audit(ctx, tx, "user", actor.UserID, "rule.create", "rule", ruleID,
		map[string]any{"kind": req.Kind, "prefix": pre.String(), "node_id": nodeID, "reason": req.Reason}, ipString(r))
	if err := tx.Commit(ctx); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": ruleID, "prefix": pre.String()})
}

func (a *App) revokeRule(w http.ResponseWriter, r *http.Request, actor Actor) {
	ctx := r.Context()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	defer tx.Rollback(ctx)
	var nodeID string
	if err := tx.QueryRow(ctx, `SELECT node_id::text FROM rules WHERE id = $1::uuid AND revoked_at IS NULL`,
		r.PathValue("id")).Scan(&nodeID); err != nil {
		writeErr(w, http.StatusNotFound, "aktive regel nicht gefunden")
		return
	}
	if err := lockNode(ctx, tx, nodeID); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	tag, err := tx.Exec(ctx, `UPDATE rules SET revoked_at = now(), revoked_by = $2::uuid
		WHERE id = $1::uuid AND revoked_at IS NULL`, r.PathValue("id"), actor.UserID)
	if err != nil || tag.RowsAffected() == 0 {
		writeErr(w, http.StatusConflict, "regel wurde bereits widerrufen")
		return
	}
	if _, err := tx.Exec(ctx, `INSERT INTO rule_events (rule_id, action, actor_id) VALUES ($1::uuid, 'revoked', $2)`,
		r.PathValue("id"), actor.UserID); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	if err := a.publishPolicy(ctx, tx, nodeID, "Regel widerrufen", actor.UserID); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "policy abgelehnt: "+err.Error())
		return
	}
	a.audit(ctx, tx, "user", actor.UserID, "rule.revoke", "rule", r.PathValue("id"), nil, ipString(r))
	if err := tx.Commit(ctx); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "widerrufen"})
}

func (a *App) ruleHistory(w http.ResponseWriter, r *http.Request, _ Actor) {
	rows, err := a.db.Query(r.Context(), `SELECT ts, action, actor_id, details::text FROM rule_events
		WHERE rule_id = $1::uuid ORDER BY ts`, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "abfrage fehlgeschlagen")
		return
	}
	defer rows.Close()
	type ev struct {
		TS      time.Time       `json:"ts"`
		Action  string          `json:"action"`
		ActorID string          `json:"actor_id"`
		Details json.RawMessage `json:"details"`
	}
	out := []ev{}
	for rows.Next() {
		var e ev
		var d string
		if err := rows.Scan(&e.TS, &e.Action, &e.ActorID, &d); err != nil {
			writeErr(w, http.StatusInternalServerError, "lesefehler")
			return
		}
		e.Details = json.RawMessage(d)
		out = append(out, e)
	}
	writeJSON(w, http.StatusOK, out)
}

// --- Policy versions -------------------------------------------------------------------

func (a *App) listPolicies(w http.ResponseWriter, r *http.Request, _ Actor) {
	rows, err := a.db.Query(r.Context(), `SELECT version, sha256, note, created_by, created_at FROM policy_versions
		WHERE node_id = $1::uuid ORDER BY version DESC LIMIT 50`, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "abfrage fehlgeschlagen")
		return
	}
	defer rows.Close()
	type pv struct {
		Version   int64     `json:"version"`
		SHA256    string    `json:"sha256"`
		Note      string    `json:"note"`
		CreatedBy string    `json:"created_by"`
		CreatedAt time.Time `json:"created_at"`
	}
	out := []pv{}
	for rows.Next() {
		var v pv
		if err := rows.Scan(&v.Version, &v.SHA256, &v.Note, &v.CreatedBy, &v.CreatedAt); err != nil {
			writeErr(w, http.StatusInternalServerError, "lesefehler")
			return
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// rollbackPolicy re-publishes an earlier version as a new, freshly signed version.
// Version numbers only increase, so agents never confuse an old policy with a new one.
func (a *App) rollbackPolicy(w http.ResponseWriter, r *http.Request, actor Actor) {
	var target int64
	if _, err := fmt.Sscanf(r.PathValue("version"), "%d", &target); err != nil || target < 1 {
		writeErr(w, http.StatusBadRequest, "ungültige version")
		return
	}
	ctx := r.Context()
	nodeID := r.PathValue("id")
	tx, err := a.db.Begin(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	defer tx.Rollback(ctx)
	if err := lockNode(ctx, tx, nodeID); err != nil {
		writeErr(w, http.StatusNotFound, "node nicht gefunden")
		return
	}
	var body string
	if err := tx.QueryRow(ctx, `SELECT body FROM policy_versions WHERE node_id = $1::uuid AND version = $2`,
		nodeID, target).Scan(&body); err != nil {
		writeErr(w, http.StatusNotFound, "version nicht gefunden")
		return
	}
	var old policy.Policy
	if err := json.Unmarshal([]byte(body), &old); err != nil {
		writeErr(w, http.StatusInternalServerError, "gespeicherte version beschädigt")
		return
	}
	var next int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) + 1 FROM policy_versions WHERE node_id = $1::uuid`, nodeID).Scan(&next); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	old.Version = next
	old.IssuedAt = time.Now().UTC()
	var cidrsJSON string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(array_to_json(management_cidrs)::text, '[]') FROM nodes WHERE id = $1::uuid`, nodeID).Scan(&cidrsJSON); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	var cidrs []string
	_ = json.Unmarshal([]byte(cidrsJSON), &cidrs)
	if err := a.storePolicy(ctx, tx, nodeID, &old, cidrs, fmt.Sprintf("Rollback auf Version %d", target), actor.UserID); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "rollback abgelehnt: "+err.Error())
		return
	}
	a.audit(ctx, tx, "user", actor.UserID, "policy.rollback", "node", nodeID, map[string]any{"from_version": target, "new_version": next}, ipString(r))
	if err := tx.Commit(ctx); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"version": next, "restored_from": target})
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
