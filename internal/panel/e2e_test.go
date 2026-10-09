package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vaktikos/ddos-prot/internal/agent"
	"github.com/vaktikos/ddos-prot/internal/identity"
	"github.com/vaktikos/ddos-prot/internal/nft"
	"github.com/vaktikos/ddos-prot/internal/store"
)

// e2eRules is the firewall stand-in for the agent under test.
type e2eRules struct {
	scripts  []string
	counters map[string]nft.Counter
}

func (r *e2eRules) Apply(s string) error {
	r.scripts = append(r.scripts, s)
	return nil
}
func (r *e2eRules) Counters() (map[string]nft.Counter, error) {
	out := map[string]nft.Counter{}
	for k, v := range r.counters {
		out[k] = v
	}
	return out, nil
}
func (r *e2eRules) SetSize(string) (int, error) { return 0, nil }
func (r *e2eRules) Installed() bool             { return len(r.scripts) > 0 }
func (r *e2eRules) add(name string, pkts uint64) {
	c := r.counters[name]
	c.Packets += pkts
	c.Bytes += pkts * 100
	r.counters[name] = c
}
func (r *e2eRules) last() string {
	if len(r.scripts) == 0 {
		return ""
	}
	return r.scripts[len(r.scripts)-1]
}

// apiClient is a browser-like client: cookies, Origin and the CSRF header.
type apiClient struct {
	t    *testing.T
	base string
	hc   *http.Client
	csrf string
}

func newAPIClient(t *testing.T, base string) *apiClient {
	jar, _ := cookiejar.New(nil)
	return &apiClient{t: t, base: base, hc: &http.Client{Jar: jar, Timeout: 20 * time.Second}}
}

func (c *apiClient) call(method, path string, body any, opts ...func(*http.Request)) (int, []byte) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if method != http.MethodGet {
		req.Header.Set("Origin", c.base)
		if c.csrf != "" {
			req.Header.Set("X-CSRF-Token", c.csrf)
		}
	}
	for _, o := range opts {
		o(req)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func (c *apiClient) login(email, password string) {
	c.t.Helper()
	code, body := c.call(http.MethodPost, "/api/v1/auth/login", map[string]string{"email": email, "password": password})
	if code != http.StatusOK {
		c.t.Fatalf("login %s: %d %s", email, code, body)
	}
	var out struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(body, &out)
	c.csrf = out.CSRF
}

func mustOK(t *testing.T, what string, code int, body []byte, want int) {
	t.Helper()
	if code != want {
		t.Fatalf("%s: HTTP %d, erwartet %d: %s", what, code, want, body)
	}
}

// TestEndToEnd exercises the whole control loop against a real PostgreSQL database.
// It needs SS_TEST_DSN; the public schema of that database is recreated.
func TestEndToEnd(t *testing.T) {
	dsn := os.Getenv("SS_TEST_DSN")
	if dsn == "" {
		t.Skip("SS_TEST_DSN nicht gesetzt (PostgreSQL-Testdatenbank, wird geleert)")
	}
	ctx := context.Background()
	pool, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	resetSchema(t, pool)
	if err := store.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	cfg := Config{Listen: ln.Addr().String(), PublicURL: base, DatabaseURL: dsn,
		SigningKey: filepath.Join(t.TempDir(), "signing.key"), CookieSecure: false, SessionHours: 12,
		SeedEmail: "admin@example.test", SeedPassword: "correct horse battery"}
	pub, priv, err := LoadOrCreateSigningKey(cfg.SigningKey)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	app, err := New(cfg, pool, log, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.EnsureSeedAdmin(ctx); err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: app.Handler()}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	admin := newAPIClient(t, base)
	admin.login(cfg.SeedEmail, cfg.SeedPassword)

	// --- Protection profile and node enrollment ---------------------------------------
	code, body := admin.call(http.MethodPost, "/api/v1/profiles", map[string]any{
		"name": "std", "kind": "generic",
		"config": map[string]any{
			"total_pps": 100000, "syn_pps": 20000, "udp_pps": 50000, "icmp_pps": 5000,
			"confirm_seconds": 3, "clear_seconds": 5,
			"mitigation": map[string]any{"syn_rate_per_source": 100, "udp_rate_per_source": 500, "auto_block_seconds": 300},
		},
	})
	mustOK(t, "profil anlegen", code, body, http.StatusCreated)

	code, body = admin.call(http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "node-a", "mode": "auto", "management_cidrs": []string{"203.0.113.10/32"},
	})
	mustOK(t, "node anlegen", code, body, http.StatusCreated)
	var created struct {
		Node  NodeDTO `json:"node"`
		Token string  `json:"enrollment_token"`
	}
	_ = json.Unmarshal(body, &created)
	nodeID := created.Node.ID

	stateDir := t.TempDir()
	if err := agent.Enroll(ctx, agent.Config{PanelURL: base, StateDir: stateDir}, created.Token, false); err != nil {
		t.Fatalf("enrollment: %v", err)
	}
	// The token is single use.
	if err := agent.Enroll(ctx, agent.Config{PanelURL: base, StateDir: t.TempDir()}, created.Token, false); err == nil {
		t.Fatal("ein verbrauchter Enrollment-Token darf nicht erneut funktionieren")
	}

	agentCfg := agent.Config{PanelURL: base, StateDir: stateDir, NftTable: "sentinel_shield",
		ManagementCIDRs: []string{"203.0.113.10/32"}, HeartbeatSeconds: 30, DetectMillis: 1000, ApprovalTimeoutS: 900}
	client, err := agent.NewPanelClient(base, "")
	if err != nil {
		t.Fatal(err)
	}
	rules := &e2eRules{counters: map[string]nft.Counter{}}
	ag, err := agent.New(agentCfg, log, rules, nil, client)
	if err != nil {
		t.Fatal(err)
	}

	// --- Protected target publishes policy version 1 ---------------------------------
	code, body = admin.call(http.MethodPost, "/api/v1/nodes/"+nodeID+"/targets", map[string]any{
		"name": "web", "prefix": "192.0.2.10", "profile": "std",
		"services": []map[string]any{{"name": "https", "protocol": "tcp", "port": 443}},
	})
	mustOK(t, "ziel anlegen", code, body, http.StatusCreated)

	now := time.Now()
	if err := ag.Heartbeat(ctx, now); err != nil {
		t.Fatalf("erster heartbeat: %v", err)
	}
	code, body = admin.call(http.MethodGet, "/api/v1/nodes/"+nodeID, nil)
	mustOK(t, "node lesen", code, body, http.StatusOK)
	var n NodeDTO
	_ = json.Unmarshal(body, &n)
	if n.AppliedPolicyVersion != 1 || n.Status != "online" || n.SyncStatus != "synced" {
		t.Fatalf("node nach Synchronisierung: applied=%d status=%s sync=%s", n.AppliedPolicyVersion, n.Status, n.SyncStatus)
	}
	if !strings.Contains(rules.last(), "table inet sentinel_shield") {
		t.Fatal("Agent hat die signierte Policy nicht in die Firewall übernommen")
	}

	// --- Replay and forgery protection on the agent API -------------------------------
	priv2, err := identity.LoadKey(filepath.Join(stateDir, "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	hbBody := []byte(`{"agent_version":"0.1.0","applied_policy_version":1,"health":{"status":"ok"}}`)
	send := func(req *http.Request) int {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	signed, _ := http.NewRequest(http.MethodPost, base+"/agent/v1/heartbeat", bytes.NewReader(hbBody))
	if err := identity.Sign(signed, nodeID, priv2, hbBody, time.Now()); err != nil {
		t.Fatal(err)
	}
	replay, _ := http.NewRequest(http.MethodPost, base+"/agent/v1/heartbeat", bytes.NewReader(hbBody))
	for k, v := range signed.Header {
		replay.Header[k] = v
	}
	if code := send(signed); code != http.StatusOK {
		t.Fatalf("gültig signierter heartbeat abgelehnt: %d", code)
	}
	if code := send(replay); code != http.StatusUnauthorized {
		t.Fatalf("Replay wurde nicht erkannt: %d", code)
	}
	forged, _ := http.NewRequest(http.MethodPost, base+"/agent/v1/heartbeat", bytes.NewReader([]byte(`{"health":{"status":"ok"}}`)))
	if err := identity.Sign(forged, nodeID, priv2, hbBody, time.Now()); err != nil {
		t.Fatal(err)
	}
	if code := send(forged); code != http.StatusUnauthorized {
		t.Fatalf("manipulierter Body wurde akzeptiert: %d", code)
	}

	// --- Synthetic SYN flood: confirmed, mitigated automatically (mode auto) ----------
	feed := func(sec int, pkts, syn uint64) {
		for i := 0; i < sec; i++ {
			rules.add("t0_all", pkts)
			rules.add("t0_syn", syn)
			now = now.Add(time.Second)
			ag.Tick(now)
		}
	}
	feed(5, 1000, 10)
	feed(6, 60000, 50000)
	if err := ag.Heartbeat(ctx, now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rules.last(), "meter ss_t0_tcp443") {
		t.Fatal("bestätigter SYN-Flood muss im Auto-Modus eine Ratenregel auslösen")
	}
	code, body = admin.call(http.MethodGet, "/api/v1/incidents?status=open", nil)
	mustOK(t, "vorfälle lesen", code, body, http.StatusOK)
	var incidents []incidentDTO
	_ = json.Unmarshal(body, &incidents)
	if len(incidents) != 1 || incidents[0].Verdict != "confirmed_attack" || incidents[0].Category != "syn_flood" {
		t.Fatalf("erwarteter bestätigter SYN-Flood, erhalten: %+v", incidents)
	}
	incidentID := incidents[0].ID

	code, body = admin.call(http.MethodGet, "/api/v1/alerts", nil)
	mustOK(t, "alarme lesen", code, body, http.StatusOK)
	if !strings.Contains(string(body), "Bestätigter Angriff") {
		t.Fatalf("Alarm für bestätigten Angriff fehlt: %s", body)
	}
	code, body = admin.call(http.MethodGet, "/api/v1/incidents/"+incidentID, nil)
	mustOK(t, "vorfall detail", code, body, http.StatusOK)
	if !strings.Contains(string(body), `"target_series"`) || !strings.Contains(string(body), `"timeline"`) {
		t.Fatalf("Vorfallsdetail unvollständig: %s", body)
	}

	// --- Attack ends: mitigation withdrawn and incident closed ----------------------
	feed(10, 1000, 10)
	if err := ag.Heartbeat(ctx, now); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rules.last(), "meter ss_") {
		t.Fatal("nach Vorfallende muss die Ratenregel entfernt sein")
	}
	code, body = admin.call(http.MethodGet, "/api/v1/incidents?status=closed", nil)
	mustOK(t, "geschlossene vorfälle", code, body, http.StatusOK)
	if !strings.Contains(string(body), incidentID) {
		t.Fatal("beendeter Vorfall muss als geschlossen erscheinen")
	}

	// --- Approval mode: nothing is applied before an operator decides ---------------
	code, body = admin.call(http.MethodPost, "/api/v1/nodes/"+nodeID+"/mode", map[string]string{"mode": "approval"})
	mustOK(t, "modus setzen", code, body, http.StatusOK)
	if err := ag.Heartbeat(ctx, now); err != nil {
		t.Fatal(err)
	}
	feed(6, 60000, 50000)
	if strings.Contains(rules.last(), "meter ss_") {
		t.Fatal("im Freigabe-Modus darf vor Entscheidung nichts aktiv sein")
	}
	if err := ag.Heartbeat(ctx, now); err != nil {
		t.Fatal(err)
	}
	code, body = admin.call(http.MethodGet, "/api/v1/actions", nil)
	mustOK(t, "maßnahmen lesen", code, body, http.StatusOK)
	var actions []actionDTO
	_ = json.Unmarshal(body, &actions)
	var pending string
	for _, a := range actions {
		if a.Status == "pending_approval" {
			pending = a.ID
		}
	}
	if pending == "" {
		t.Fatalf("erwartet eine wartende Freigabe: %s", body)
	}
	code, body = admin.call(http.MethodPost, "/api/v1/actions/"+pending+"/approve", nil)
	mustOK(t, "freigeben", code, body, http.StatusOK)
	if err := ag.Heartbeat(ctx, now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rules.last(), "meter ss_t0_tcp443") {
		t.Fatal("freigegebene Maßnahme muss nach dem Heartbeat aktiv sein")
	}
	if err := ag.Heartbeat(ctx, now); err != nil {
		t.Fatal(err)
	}
	code, body = admin.call(http.MethodGet, "/api/v1/actions", nil)
	mustOK(t, "maßnahmen lesen", code, body, http.StatusOK)
	if !strings.Contains(string(body), `"status":"applied"`) {
		t.Fatalf("Agent muss die Anwendung zurückmelden: %s", body)
	}
	feed(10, 1000, 10) // close incident again
	if err := ag.Heartbeat(ctx, now); err != nil {
		t.Fatal(err)
	}

	// --- Management rules: deny with expiry, management protection, rollback -------
	code, body = admin.call(http.MethodPost, "/api/v1/nodes/"+nodeID+"/rules", map[string]any{
		"kind": "deny", "prefix": "198.51.100.7", "reason": "Scan-Quelle",
		"expires_at": time.Now().Add(time.Hour),
	})
	mustOK(t, "sperre anlegen", code, body, http.StatusCreated)
	var rule struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &rule)

	code, body = admin.call(http.MethodPost, "/api/v1/nodes/"+nodeID+"/rules", map[string]any{
		"kind": "deny", "prefix": "203.0.113.10", "reason": "versehentlich Management",
		"expires_at": time.Now().Add(time.Hour),
	})
	mustOK(t, "sperre des Management-Netzes", code, body, http.StatusUnprocessableEntity)

	code, body = admin.call(http.MethodPost, "/api/v1/nodes/"+nodeID+"/rules", map[string]any{
		"kind": "deny", "prefix": "198.51.100.8", "reason": "dauerhaft",
	})
	mustOK(t, "sperre ohne ablauf", code, body, http.StatusBadRequest)

	if err := ag.Heartbeat(ctx, now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rules.last(), "198.51.100.7/32 timeout") {
		t.Fatalf("Sperre fehlt im Ruleset:\n%s", rules.last())
	}
	code, body = admin.call(http.MethodPost, "/api/v1/rules/"+rule.ID+"/revoke", nil)
	mustOK(t, "sperre widerrufen", code, body, http.StatusOK)
	if err := ag.Heartbeat(ctx, now); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rules.last(), "198.51.100.7/32") {
		t.Fatal("widerrufene Sperre muss aus dem Ruleset verschwinden")
	}

	code, body = admin.call(http.MethodPost, "/api/v1/nodes/"+nodeID+"/policies/1/rollback", nil)
	mustOK(t, "rollback", code, body, http.StatusCreated)
	if err := ag.Heartbeat(ctx, now); err != nil {
		t.Fatal(err)
	}
	code, body = admin.call(http.MethodGet, "/api/v1/nodes/"+nodeID, nil)
	mustOK(t, "node lesen", code, body, http.StatusOK)
	_ = json.Unmarshal(body, &n)
	if n.AppliedPolicyVersion != n.DesiredPolicyVersion || n.SyncStatus != "synced" {
		t.Fatalf("nach Rollback nicht synchron: applied=%d desired=%d sync=%s", n.AppliedPolicyVersion, n.DesiredPolicyVersion, n.SyncStatus)
	}

	// --- Access control ---------------------------------------------------------------
	code, body = admin.call(http.MethodPost, "/api/v1/users", map[string]string{
		"email": "viewer@example.test", "password": "viewer password 123", "role": "viewer"})
	mustOK(t, "viewer anlegen", code, body, http.StatusCreated)
	viewer := newAPIClient(t, base)
	viewer.login("viewer@example.test", "viewer password 123")
	code, body = viewer.call(http.MethodPost, "/api/v1/nodes/"+nodeID+"/targets", map[string]any{
		"name": "x", "prefix": "198.51.100.20", "profile": "std"})
	mustOK(t, "viewer darf nicht schreiben", code, body, http.StatusForbidden)
	code, body = viewer.call(http.MethodGet, "/api/v1/dashboard", nil)
	mustOK(t, "viewer darf lesen", code, body, http.StatusOK)
	code, body = viewer.call(http.MethodGet, "/api/v1/audit", nil)
	mustOK(t, "viewer darf kein audit lesen", code, body, http.StatusForbidden)

	noCSRF := newAPIClient(t, base)
	noCSRF.hc.Jar = admin.hc.Jar
	code, body = noCSRF.call(http.MethodPost, "/api/v1/nodes/"+nodeID+"/mode", map[string]string{"mode": "auto"})
	mustOK(t, "CSRF-Token fehlt", code, body, http.StatusForbidden)
	code, body = admin.call(http.MethodPost, "/api/v1/nodes/"+nodeID+"/mode", map[string]string{"mode": "auto"},
		func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") })
	mustOK(t, "fremder Origin", code, body, http.StatusForbidden)

	code, body = admin.call(http.MethodPost, "/api/v1/auth/login", map[string]string{"email": "admin@example.test", "password": "wrong password!!"})
	mustOK(t, "falsches Passwort", code, body, http.StatusUnauthorized)

	// --- Dashboard and metrics come from stored measurements --------------------------
	code, body = admin.call(http.MethodGet, "/api/v1/dashboard", nil)
	mustOK(t, "dashboard", code, body, http.StatusOK)
	var dash Dashboard
	_ = json.Unmarshal(body, &dash)
	if dash.ProtectedTargets != 1 || dash.Nodes["online"] != 1 {
		t.Fatalf("dashboard: targets=%d nodes=%v", dash.ProtectedTargets, dash.Nodes)
	}
	code, body = admin.call(http.MethodGet, "/api/v1/nodes/"+nodeID+"/metrics?range=1h", nil)
	mustOK(t, "metriken", code, body, http.StatusOK)
	if !strings.Contains(string(body), "cpu_percent") {
		t.Fatalf("keine Metrikpunkte: %s", body)
	}
	code, body = admin.call(http.MethodGet, "/api/v1/nodes/"+nodeID+"/metrics?range=999y", nil)
	mustOK(t, "ungültiger zeitraum", code, body, http.StatusBadRequest)

	// --- Audit trail and node revocation ----------------------------------------------
	code, body = admin.call(http.MethodGet, "/api/v1/audit?limit=200", nil)
	mustOK(t, "audit", code, body, http.StatusOK)
	for _, want := range []string{"target.create", "rule.create", "policy.rollback", "action.approved", "node.enroll"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("audit-eintrag %q fehlt", want)
		}
	}

	code, body = admin.call(http.MethodPost, "/api/v1/nodes/"+nodeID+"/revoke", nil)
	mustOK(t, "widerrufen", code, body, http.StatusOK)
	if err := ag.Heartbeat(ctx, now); err == nil {
		t.Fatal("widerrufener node darf keinen heartbeat mehr senden")
	}
}

func resetSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("testdatenbank zurücksetzen: %v", err)
	}
}

func envValue(key string) string { return os.Getenv(key) }
