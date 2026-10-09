package panel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/vaktikos/ddos-prot/internal/netaddr"
	"github.com/vaktikos/ddos-prot/internal/policy"
)

const enrollmentTTL = 24 * time.Hour

// NodeDTO is the API representation of a node.
type NodeDTO struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	LocationID           *string         `json:"location_id"`
	LocationName         *string         `json:"location_name"`
	Status               string          `json:"status"`
	Mode                 string          `json:"mode"`
	Hostname             string          `json:"hostname"`
	AgentVersion         string          `json:"agent_version"`
	ManagementCIDRs      []string        `json:"management_cidrs"`
	Health               json.RawMessage `json:"health"`
	Guards               json.RawMessage `json:"guards"`
	L7                   json.RawMessage `json:"l7"`
	AppliedPolicyVersion int64           `json:"applied_policy_version"`
	DesiredPolicyVersion int64           `json:"desired_policy_version"`
	SyncStatus           string          `json:"sync_status"`
	SyncError            string          `json:"sync_error"`
	LastHeartbeatAt      *time.Time      `json:"last_heartbeat_at"`
	Enrolled             bool            `json:"enrolled"`
	CreatedAt            time.Time       `json:"created_at"`
}

const nodeSelect = `
	SELECT n.id::text, n.name, n.location_id::text, l.name, n.status, n.mode, n.hostname, n.agent_version,
	       COALESCE(array_to_json(n.management_cidrs)::text, '[]'), n.health::text, n.guards::text, n.l7::text,
	       n.applied_policy_version, n.desired_policy_version, n.sync_status, n.sync_error,
	       n.last_heartbeat_at, n.public_key IS NOT NULL, n.created_at
	FROM nodes n LEFT JOIN locations l ON l.id = n.location_id`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanNode(row rowScanner) (NodeDTO, error) {
	var n NodeDTO
	var cidrs, health, guards, l7 string
	err := row.Scan(&n.ID, &n.Name, &n.LocationID, &n.LocationName, &n.Status, &n.Mode, &n.Hostname, &n.AgentVersion,
		&cidrs, &health, &guards, &l7, &n.AppliedPolicyVersion, &n.DesiredPolicyVersion, &n.SyncStatus, &n.SyncError,
		&n.LastHeartbeatAt, &n.Enrolled, &n.CreatedAt)
	if err != nil {
		return n, err
	}
	var list []string
	if err := json.Unmarshal([]byte(cidrs), &list); err != nil {
		return n, err
	}
	n.ManagementCIDRs = list
	n.Health = json.RawMessage(health)
	n.Guards = json.RawMessage(guards)
	n.L7 = json.RawMessage(l7)
	return n, nil
}

func (a *App) listNodes(w http.ResponseWriter, r *http.Request, _ Actor) {
	rows, err := a.db.Query(r.Context(), nodeSelect+` ORDER BY n.name`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "abfrage fehlgeschlagen")
		return
	}
	defer rows.Close()
	out := []NodeDTO{}
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "lesefehler")
			return
		}
		out = append(out, n)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) getNode(w http.ResponseWriter, r *http.Request, _ Actor) {
	n, err := scanNode(a.db.QueryRow(r.Context(), nodeSelect+` WHERE n.id = $1::uuid`, r.PathValue("id")))
	if errors.Is(err, pgx.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "node nicht gefunden")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "abfrage fehlgeschlagen")
		return
	}
	writeJSON(w, http.StatusOK, n)
}

type createNodeRequest struct {
	Name            string   `json:"name"`
	LocationID      *string  `json:"location_id"`
	Mode            string   `json:"mode"`
	ManagementCIDRs []string `json:"management_cidrs"`
}

// parseCIDRs validates management networks. They are infrastructure access paths,
// so they are required to be specific.
func parseCIDRs(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, errors.New("management_cidrs: mindestens ein Netz angeben")
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		p, err := netaddr.ParsePrefix(s)
		if err == nil {
			// A management network is never blocked, so a catch-all would switch blocking off.
			err = netaddr.ValidateProtected(p)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, p.String())
	}
	return out, nil
}

func (a *App) createNode(w http.ResponseWriter, r *http.Request, actor Actor) {
	var req createNodeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 100 {
		writeErr(w, http.StatusBadRequest, "name ist erforderlich (max. 100 Zeichen)")
		return
	}
	if req.Mode == "" {
		req.Mode = policy.ModeDryRun
	}
	if req.Mode != policy.ModeDryRun && req.Mode != policy.ModeApproval && req.Mode != policy.ModeAuto {
		writeErr(w, http.StatusBadRequest, "unbekannter Modus")
		return
	}
	cidrs, err := parseCIDRs(req.ManagementCIDRs)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	token, hash, err := randomToken(32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	ctx := r.Context()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	defer tx.Rollback(ctx)
	var id string
	err = tx.QueryRow(ctx, `INSERT INTO nodes (name, location_id, mode, management_cidrs, enrollment_hash, enrollment_expires_at)
		VALUES ($1, $2::uuid, $3, $4::cidr[], $5, $6) RETURNING id::text`,
		req.Name, req.LocationID, req.Mode, cidrs, hash, time.Now().Add(enrollmentTTL)).Scan(&id)
	if err != nil {
		writeErr(w, http.StatusConflict, "node konnte nicht angelegt werden (Name bereits vergeben oder Standort ungültig)")
		return
	}
	a.audit(ctx, tx, "user", actor.UserID, "node.create", "node", id, map[string]any{"name": req.Name, "mode": req.Mode}, ipString(r))
	if err := tx.Commit(ctx); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	n, _ := scanNode(a.db.QueryRow(ctx, nodeSelect+` WHERE n.id = $1::uuid`, id))
	writeJSON(w, http.StatusCreated, map[string]any{
		"node":             n,
		"enrollment_token": token, // shown exactly once; only its hash is stored
		"expires_at":       time.Now().Add(enrollmentTTL),
	})
}

func (a *App) newEnrollmentToken(w http.ResponseWriter, r *http.Request, actor Actor) {
	token, hash, err := randomToken(32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	tag, err := a.db.Exec(r.Context(), `UPDATE nodes SET enrollment_hash = $2, enrollment_expires_at = $3, updated_at = now()
		WHERE id = $1::uuid AND public_key IS NULL AND status <> 'revoked'`,
		r.PathValue("id"), hash, time.Now().Add(enrollmentTTL))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	if tag.RowsAffected() == 0 {
		writeErr(w, http.StatusConflict, "node ist bereits eingeschrieben oder nicht vorhanden; ein neuer Token ist nur vor der Registrierung möglich")
		return
	}
	a.audit(r.Context(), a.db, "user", actor.UserID, "node.enrollment_token", "node", r.PathValue("id"), nil, ipString(r))
	writeJSON(w, http.StatusOK, map[string]any{"enrollment_token": token, "expires_at": time.Now().Add(enrollmentTTL)})
}

type updateNodeRequest struct {
	Name            *string  `json:"name"`
	LocationID      *string  `json:"location_id"`
	ManagementCIDRs []string `json:"management_cidrs"`
}

func (a *App) updateNode(w http.ResponseWriter, r *http.Request, actor Actor) {
	var req updateNodeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	defer tx.Rollback(ctx)
	id := r.PathValue("id")
	var cidrs []string
	if req.ManagementCIDRs != nil {
		cidrs, err = parseCIDRs(req.ManagementCIDRs)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := lockNode(ctx, tx, id); err != nil {
		writeErr(w, http.StatusNotFound, "node nicht gefunden")
		return
	}
	tag, err := tx.Exec(ctx, `UPDATE nodes SET
		name = COALESCE($2, name),
		location_id = CASE WHEN $3::boolean THEN $4::uuid ELSE location_id END,
		management_cidrs = CASE WHEN $5::boolean THEN $6::cidr[] ELSE management_cidrs END,
		updated_at = now()
		WHERE id = $1::uuid`,
		id, req.Name, req.LocationID != nil, req.LocationID, req.ManagementCIDRs != nil, cidrs)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "änderung ungültig (Name doppelt oder Standort unbekannt)")
		return
	}
	if tag.RowsAffected() == 0 {
		writeErr(w, http.StatusNotFound, "node nicht gefunden")
		return
	}
	if req.ManagementCIDRs != nil {
		if err := a.publishPolicy(ctx, tx, id, "Management-Netze geändert", actor.UserID); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, "policy abgelehnt: "+err.Error())
			return
		}
	}
	a.audit(ctx, tx, "user", actor.UserID, "node.update", "node", id, map[string]any{"management_cidrs": req.ManagementCIDRs}, ipString(r))
	if err := tx.Commit(ctx); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	n, _ := scanNode(a.db.QueryRow(ctx, nodeSelect+` WHERE n.id = $1::uuid`, id))
	writeJSON(w, http.StatusOK, n)
}

type modeRequest struct {
	Mode string `json:"mode"`
}

func (a *App) setMode(w http.ResponseWriter, r *http.Request, actor Actor) {
	var req modeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Mode != policy.ModeDryRun && req.Mode != policy.ModeApproval && req.Mode != policy.ModeAuto {
		writeErr(w, http.StatusBadRequest, "unbekannter Modus")
		return
	}
	ctx := r.Context()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	defer tx.Rollback(ctx)
	id := r.PathValue("id")
	if err := lockNode(ctx, tx, id); err != nil {
		writeErr(w, http.StatusNotFound, "node nicht gefunden")
		return
	}
	var previous string
	if err := tx.QueryRow(ctx, `SELECT mode FROM nodes WHERE id = $1::uuid`, id).Scan(&previous); err != nil {
		writeErr(w, http.StatusNotFound, "node nicht gefunden")
		return
	}
	if _, err := tx.Exec(ctx, `UPDATE nodes SET mode = $2, updated_at = now() WHERE id = $1::uuid`, id, req.Mode); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	if err := a.publishPolicy(ctx, tx, id, fmt.Sprintf("Modus %s -> %s", previous, req.Mode), actor.UserID); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "policy abgelehnt: "+err.Error())
		return
	}
	a.audit(ctx, tx, "user", actor.UserID, "node.mode", "node", id, map[string]any{"from": previous, "to": req.Mode}, ipString(r))
	if err := tx.Commit(ctx); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"mode": req.Mode})
}

func (a *App) revokeNode(w http.ResponseWriter, r *http.Request, actor Actor) {
	id := r.PathValue("id")
	tag, err := a.db.Exec(r.Context(), `UPDATE nodes SET status = 'revoked', updated_at = now() WHERE id = $1::uuid`, id)
	if err != nil || tag.RowsAffected() == 0 {
		writeErr(w, http.StatusNotFound, "node nicht gefunden")
		return
	}
	a.audit(r.Context(), a.db, "user", actor.UserID, "node.revoke", "node", id, nil, ipString(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// --- Users ----------------------------------------------------------------------

type userDTO struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	Disabled    bool       `json:"disabled"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

func (a *App) listUsers(w http.ResponseWriter, r *http.Request, _ Actor) {
	rows, err := a.db.Query(r.Context(), `SELECT id::text, email, role, disabled, last_login_at FROM users ORDER BY email`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "abfrage fehlgeschlagen")
		return
	}
	defer rows.Close()
	out := []userDTO{}
	for rows.Next() {
		var u userDTO
		if err := rows.Scan(&u.ID, &u.Email, &u.Role, &u.Disabled, &u.LastLoginAt); err != nil {
			writeErr(w, http.StatusInternalServerError, "lesefehler")
			return
		}
		out = append(out, u)
	}
	writeJSON(w, http.StatusOK, out)
}

type createUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (a *App) createUser(w http.ResponseWriter, r *http.Request, actor Actor) {
	var req createUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if len(req.Email) < 3 || len(req.Email) > 254 || !strings.Contains(req.Email, "@") {
		writeErr(w, http.StatusBadRequest, "ungültige E-Mail-Adresse")
		return
	}
	if _, ok := roleRank[req.Role]; !ok {
		writeErr(w, http.StatusBadRequest, "unbekannte Rolle")
		return
	}
	if err := validPassword(req.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	var id string
	if err := a.db.QueryRow(r.Context(), `INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id::text`,
		req.Email, hash, req.Role).Scan(&id); err != nil {
		writeErr(w, http.StatusConflict, "benutzer existiert bereits")
		return
	}
	a.audit(r.Context(), a.db, "user", actor.UserID, "user.create", "user", id, map[string]any{"role": req.Role}, ipString(r))
	writeJSON(w, http.StatusCreated, userDTO{ID: id, Email: req.Email, Role: req.Role})
}

func (a *App) disableUser(w http.ResponseWriter, r *http.Request, actor Actor) {
	id := r.PathValue("id")
	if id == actor.UserID {
		writeErr(w, http.StatusBadRequest, "das eigene Konto kann nicht deaktiviert werden")
		return
	}
	ctx := r.Context()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE users SET disabled = true WHERE id = $1::uuid`, id)
	if err != nil || tag.RowsAffected() == 0 {
		writeErr(w, http.StatusNotFound, "benutzer nicht gefunden")
		return
	}
	if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1::uuid`, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	a.audit(ctx, tx, "user", actor.UserID, "user.disable", "user", id, nil, ipString(r))
	if err := tx.Commit(ctx); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deaktiviert"})
}

// --- Locations and profiles ----------------------------------------------------------

type locationDTO struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (a *App) listLocations(w http.ResponseWriter, r *http.Request, _ Actor) {
	rows, err := a.db.Query(r.Context(), `SELECT id::text, name, description FROM locations ORDER BY name`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "abfrage fehlgeschlagen")
		return
	}
	defer rows.Close()
	out := []locationDTO{}
	for rows.Next() {
		var l locationDTO
		if err := rows.Scan(&l.ID, &l.Name, &l.Description); err != nil {
			writeErr(w, http.StatusInternalServerError, "lesefehler")
			return
		}
		out = append(out, l)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) createLocation(w http.ResponseWriter, r *http.Request, actor Actor) {
	var l locationDTO
	if err := decodeJSON(r, &l); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	l.Name = strings.TrimSpace(l.Name)
	if l.Name == "" || len(l.Name) > 100 || len(l.Description) > 500 {
		writeErr(w, http.StatusBadRequest, "name (max. 100) und beschreibung (max. 500) prüfen")
		return
	}
	if err := a.db.QueryRow(r.Context(), `INSERT INTO locations (name, description) VALUES ($1, $2) RETURNING id::text`,
		l.Name, l.Description).Scan(&l.ID); err != nil {
		writeErr(w, http.StatusConflict, "standort existiert bereits")
		return
	}
	a.audit(r.Context(), a.db, "user", actor.UserID, "location.create", "location", l.ID, map[string]any{"name": l.Name}, ipString(r))
	writeJSON(w, http.StatusCreated, l)
}

type profileDTO struct {
	ID     string         `json:"id"`
	Name   string         `json:"name"`
	Kind   string         `json:"kind"`
	Config policy.Profile `json:"config"`
}

func (a *App) listProfiles(w http.ResponseWriter, r *http.Request, _ Actor) {
	rows, err := a.db.Query(r.Context(), `SELECT id::text, name, kind, config::text FROM protection_profiles ORDER BY name`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "abfrage fehlgeschlagen")
		return
	}
	defer rows.Close()
	out := []profileDTO{}
	for rows.Next() {
		var p profileDTO
		var raw string
		if err := rows.Scan(&p.ID, &p.Name, &p.Kind, &raw); err != nil {
			writeErr(w, http.StatusInternalServerError, "lesefehler")
			return
		}
		if err := json.Unmarshal([]byte(raw), &p.Config); err != nil {
			writeErr(w, http.StatusInternalServerError, "profil beschädigt")
			return
		}
		out = append(out, p)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) createProfile(w http.ResponseWriter, r *http.Request, actor Actor) {
	var p profileDTO
	if err := decodeJSON(r, &p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p.Name = strings.TrimSpace(p.Name)
	p.Config.Kind = p.Kind
	if err := policy.ValidateProfile(p.Name, p.Config); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	raw, err := json.Marshal(p.Config)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	if err := a.db.QueryRow(r.Context(), `INSERT INTO protection_profiles (name, kind, config) VALUES ($1, $2, $3::jsonb) RETURNING id::text`,
		p.Name, p.Kind, string(raw)).Scan(&p.ID); err != nil {
		writeErr(w, http.StatusConflict, "profil existiert bereits oder ist ungültig")
		return
	}
	a.audit(r.Context(), a.db, "user", actor.UserID, "profile.create", "profile", p.ID, map[string]any{"name": p.Name}, ipString(r))
	writeJSON(w, http.StatusCreated, p)
}
