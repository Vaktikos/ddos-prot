package panel

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Roles, ordered by privilege.
const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

var roleRank = map[string]int{RoleViewer: 1, RoleOperator: 2, RoleAdmin: 3}

// App is the panel's runtime state. It is safe for concurrent use.
type App struct {
	cfg     Config
	db      *pgxpool.Pool
	log     *slog.Logger
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	now     func() time.Time
	origin  string
	apiRL   *limiter
	loginRL *limiter
	agentRL *limiter
}

// Actor is the authenticated caller of a management request.
type Actor struct {
	UserID string
	Email  string
	Role   string
	CSRF   string
}

// New creates the application.
func New(cfg Config, db *pgxpool.Pool, log *slog.Logger, pub ed25519.PublicKey, priv ed25519.PrivateKey) (*App, error) {
	u, err := url.Parse(cfg.PublicURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("PANEL_PUBLIC_URL ungültig: %q", cfg.PublicURL)
	}
	return &App{
		cfg: cfg, db: db, log: log, pub: pub, priv: priv, now: time.Now,
		origin:  u.Scheme + "://" + u.Host,
		apiRL:   newLimiter(20, 300),     // 20/s sustained, burst 300 per client
		loginRL: newLimiter(10.0/60, 10), // 10 attempts per minute per client
		agentRL: newLimiter(2, 120),      // per node: 2/s sustained, burst 120
	}, nil
}

// Handler builds the HTTP routing table and middleware chain.
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()

	// Authentication
	mux.HandleFunc("POST /api/v1/auth/login", a.login)
	mux.HandleFunc("POST /api/v1/auth/logout", a.withSession(RoleViewer, a.logout))
	mux.HandleFunc("GET /api/v1/auth/me", a.withSession(RoleViewer, a.me))
	mux.HandleFunc("POST /api/v1/auth/mfa/enroll", a.withSession(RoleViewer, a.mfaEnroll))
	mux.HandleFunc("POST /api/v1/auth/mfa/enable", a.withSession(RoleViewer, a.mfaEnable))
	mux.HandleFunc("POST /api/v1/auth/mfa/disable", a.withSession(RoleViewer, a.mfaDisable))

	// Read access (viewer and up)
	mux.HandleFunc("GET /api/v1/dashboard", a.withSession(RoleViewer, a.dashboard))
	mux.HandleFunc("GET /api/v1/nodes", a.withSession(RoleViewer, a.listNodes))
	mux.HandleFunc("GET /api/v1/nodes/{id}", a.withSession(RoleViewer, a.getNode))
	mux.HandleFunc("GET /api/v1/nodes/{id}/targets", a.withSession(RoleViewer, a.listTargets))
	mux.HandleFunc("GET /api/v1/nodes/{id}/rules", a.withSession(RoleViewer, a.listRules))
	mux.HandleFunc("GET /api/v1/nodes/{id}/policies", a.withSession(RoleViewer, a.listPolicies))
	mux.HandleFunc("GET /api/v1/nodes/{id}/metrics", a.withSession(RoleViewer, a.nodeSeries))
	mux.HandleFunc("GET /api/v1/targets/{id}/metrics", a.withSession(RoleViewer, a.targetSeries))
	mux.HandleFunc("GET /api/v1/rules/{id}/history", a.withSession(RoleViewer, a.ruleHistory))
	mux.HandleFunc("GET /api/v1/profiles", a.withSession(RoleViewer, a.listProfiles))
	mux.HandleFunc("GET /api/v1/locations", a.withSession(RoleViewer, a.listLocations))
	mux.HandleFunc("GET /api/v1/incidents", a.withSession(RoleViewer, a.listIncidents))
	mux.HandleFunc("GET /api/v1/incidents/{id}", a.withSession(RoleViewer, a.getIncident))
	mux.HandleFunc("GET /api/v1/actions", a.withSession(RoleViewer, a.listActions))
	mux.HandleFunc("GET /api/v1/alerts", a.withSession(RoleViewer, a.listAlerts))
	mux.HandleFunc("GET /api/v1/audit", a.withSession(RoleAdmin, a.listAudit))
	mux.HandleFunc("GET /api/v1/users", a.withSession(RoleAdmin, a.listUsers))

	// Operator actions
	mux.HandleFunc("POST /api/v1/nodes/{id}/mode", a.withSession(RoleOperator, a.setMode))
	mux.HandleFunc("POST /api/v1/nodes/{id}/targets", a.withSession(RoleOperator, a.createTarget))
	mux.HandleFunc("DELETE /api/v1/targets/{id}", a.withSession(RoleOperator, a.deleteTarget))
	mux.HandleFunc("POST /api/v1/nodes/{id}/rules", a.withSession(RoleOperator, a.createRule))
	mux.HandleFunc("POST /api/v1/rules/{id}/revoke", a.withSession(RoleOperator, a.revokeRule))
	mux.HandleFunc("POST /api/v1/nodes/{id}/policies/{version}/rollback", a.withSession(RoleOperator, a.rollbackPolicy))
	mux.HandleFunc("POST /api/v1/actions/{id}/approve", a.withSession(RoleOperator, a.decideAction("approved")))
	mux.HandleFunc("POST /api/v1/actions/{id}/reject", a.withSession(RoleOperator, a.decideAction("rejected")))
	mux.HandleFunc("POST /api/v1/alerts/{id}/ack", a.withSession(RoleOperator, a.ackAlert))

	// Administration
	mux.HandleFunc("POST /api/v1/nodes", a.withSession(RoleAdmin, a.createNode))
	mux.HandleFunc("PATCH /api/v1/nodes/{id}", a.withSession(RoleAdmin, a.updateNode))
	mux.HandleFunc("POST /api/v1/nodes/{id}/revoke", a.withSession(RoleAdmin, a.revokeNode))
	mux.HandleFunc("POST /api/v1/nodes/{id}/enrollment-token", a.withSession(RoleAdmin, a.newEnrollmentToken))
	mux.HandleFunc("POST /api/v1/profiles", a.withSession(RoleAdmin, a.createProfile))
	mux.HandleFunc("POST /api/v1/locations", a.withSession(RoleAdmin, a.createLocation))
	mux.HandleFunc("POST /api/v1/users", a.withSession(RoleAdmin, a.createUser))
	mux.HandleFunc("POST /api/v1/users/{id}/disable", a.withSession(RoleAdmin, a.disableUser))

	// Agent API: authenticated by Ed25519 request signatures, not by sessions.
	mux.HandleFunc("POST /agent/v1/enroll", a.enroll)
	mux.HandleFunc("POST /agent/v1/heartbeat", a.heartbeat)
	mux.HandleFunc("GET /agent/v1/policy", a.agentPolicy)

	mux.HandleFunc("GET /healthz", a.healthz)
	mux.HandleFunc("GET /readyz", a.readyz)

	var h http.Handler = mux
	if a.cfg.WebDir != "" {
		h = a.withStatic(mux)
	}
	return a.securityHeaders(h)
}

func (a *App) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/agent/") {
			h.Set("Cache-Control", "no-store")
		}
		limit := int64(1 << 20)
		if r.URL.Path == "/agent/v1/heartbeat" {
			limit = maxAgentBody // agents batch events; see agent.maxEventsPerHeartbeat
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

func (a *App) withStatic(api http.Handler) http.Handler {
	files := http.FileServer(http.Dir(a.cfg.WebDir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/agent/") || r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			api.ServeHTTP(w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
}

// --- JSON helpers -------------------------------------------------------------

type apiError struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apiError{Error: msg})
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("ungültiger JSON-Body: %w", err)
	}
	if dec.More() {
		return errors.New("ungültiger JSON-Body: mehrere Dokumente")
	}
	return nil
}

// clientIP uses the TCP peer address only. Forwarded headers are not trusted by default,
// because a client could spoof them to bypass rate limits.
func clientIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

func ipString(r *http.Request) *string {
	a := clientIP(r)
	if !a.IsValid() {
		return nil
	}
	s := a.String()
	return &s
}

// --- Health ---------------------------------------------------------------------

func (a *App) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": "0.1.0"})
}

func (a *App) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := a.db.Ping(ctx); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "datenbank nicht bereit")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// --- Authorization ----------------------------------------------------------------

type actorHandler func(w http.ResponseWriter, r *http.Request, actor Actor)

// withSession authenticates the cookie, enforces the minimum role, and applies CSRF
// protection to state-changing requests.
func (a *App) withSession(min string, h actorHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.apiRL.allow(clientIP(r).String()) {
			writeErr(w, http.StatusTooManyRequests, "zu viele Anfragen")
			return
		}
		actor, err := a.sessionActor(r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "nicht angemeldet")
			return
		}
		if roleRank[actor.Role] < roleRank[min] {
			writeErr(w, http.StatusForbidden, "keine Berechtigung für diese Aktion")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !a.originOK(r) {
				writeErr(w, http.StatusForbidden, "Origin nicht erlaubt")
				return
			}
			given := r.Header.Get("X-CSRF-Token")
			if given == "" || subtle.ConstantTimeCompare([]byte(given), []byte(actor.CSRF)) != 1 {
				writeErr(w, http.StatusForbidden, "CSRF-Token fehlt oder ist ungültig")
				return
			}
		}
		h(w, r, actor)
	}
}

func (a *App) originOK(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	return origin == a.origin
}

// audit writes one security-relevant event. Failures are logged but do not
// hide the result of the action itself, which has already been committed.
func (a *App) audit(ctx context.Context, q execer, actorType, actorID, action, targetType, targetID string, details map[string]any, ip *string) {
	if details == nil {
		details = map[string]any{}
	}
	raw, _ := json.Marshal(details)
	if _, err := q.Exec(ctx, `INSERT INTO audit_log (actor_type, actor_id, action, target_type, target_id, details, client_ip)
		VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::inet)`, actorType, actorID, action, targetType, targetID, string(raw), ip); err != nil {
		a.log.Error("audit-eintrag fehlgeschlagen", "action", action, "err", err)
	}
}

// execer is satisfied by both pgxpool.Pool and pgx.Tx.
type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// limiter is a per-key token bucket. It bounds memory by resetting when it grows large.
type limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(rate, burst float64) *limiter {
	return &limiter{rate: rate, burst: burst, buckets: map[string]*bucket{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.buckets) > 50000 {
		l.buckets = map[string]*bucket{}
	}
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
