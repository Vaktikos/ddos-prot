package panel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vaktikos/ddos-prot/internal/signer"

	"github.com/vaktikos/ddos-prot/internal/agent"
	"github.com/vaktikos/ddos-prot/internal/identity"
	"github.com/vaktikos/ddos-prot/internal/nft"
	"github.com/vaktikos/ddos-prot/internal/store"
)

type testPanel struct {
	base    string
	cfg     Config
	app     *App
	admin   *apiClient
	pool    *pgxpool.Pool
	handler atomic.Value // http.Handler; swapped to simulate a panel restart with other keys
}

// swapSigner replaces the running panel with one that signs with sg and announces next,
// on the same database, like a restart with a changed configuration.
func (tp *testPanel) swapSigner(t *testing.T, sg signer.Signer, next ed25519.PublicKey) {
	t.Helper()
	dk, _ := LoadOrCreateDataKey(filepath.Join(t.TempDir(), "dk"))
	app, err := NewWithSigner(tp.cfg, tp.pool, slog.New(slog.NewTextHandler(io.Discard, nil)), sg, dk, next)
	if err != nil {
		t.Fatal(err)
	}
	tp.app = app
	tp.handler.Store(app.Handler())
}

// startTestPanel runs a panel on a random port against a freshly reset test database.
func startTestPanel(t *testing.T) *testPanel {
	t.Helper()
	dsn := envDSN(t)
	ctx := context.Background()
	pool, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	resetSchema(t, pool)
	if err := store.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	cfg := Config{PublicURL: base, DatabaseURL: dsn, SigningKey: filepath.Join(t.TempDir(), "k"),
		SessionHours: 12, SeedEmail: "admin@example.test", SeedPassword: "correct horse battery"}
	pub, priv, err := LoadOrCreateSigningKey(cfg.SigningKey)
	if err != nil {
		t.Fatal(err)
	}
	app, err := New(cfg, pool, slog.New(slog.NewTextHandler(io.Discard, nil)), pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.EnsureSeedAdmin(ctx); err != nil {
		t.Fatal(err)
	}
	tp := &testPanel{base: base, cfg: cfg, app: app, pool: pool}
	tp.handler.Store(app.Handler())
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tp.handler.Load().(http.Handler).ServeHTTP(w, r)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	tp.admin = newAPIClient(t, base)
	tp.admin.login(cfg.SeedEmail, cfg.SeedPassword)
	return tp
}

func TestLoginAccountLockout(t *testing.T) {
	tp := startTestPanel(t)
	c := newAPIClient(t, tp.base)
	for i := 0; i < maxFailedLogins; i++ {
		code, body := c.call(http.MethodPost, "/api/v1/auth/login", map[string]string{"email": tp.cfg.SeedEmail, "password": "wrong password!!"})
		mustOK(t, "falsches Passwort", code, body, http.StatusUnauthorized)
	}
	// Even the right password is refused while the account is locked.
	code, body := c.call(http.MethodPost, "/api/v1/auth/login", map[string]string{"email": tp.cfg.SeedEmail, "password": tp.cfg.SeedPassword})
	mustOK(t, "gesperrtes Konto", code, body, http.StatusUnauthorized)
}

func TestLoginIsRateLimitedPerClient(t *testing.T) {
	tp := startTestPanel(t)
	c := newAPIClient(t, tp.base)
	limited := 0
	for i := 0; i < 25; i++ {
		code, _ := c.call(http.MethodPost, "/api/v1/auth/login", map[string]string{"email": "nobody@example.test", "password": "wrong password!!"})
		if code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("nach vielen Versuchen muss die Anmeldung mit 429 begrenzt werden")
	}
}

type rotationEnv struct {
	tp       *testPanel
	nodeID   string
	stateDir string
	cfg      agent.Config
	ag       *agent.Agent
	rules    *e2eRules
}

func newRotationEnv(t *testing.T) *rotationEnv {
	t.Helper()
	tp := startTestPanel(t)
	code, body := tp.admin.call(http.MethodPost, "/api/v1/nodes", map[string]any{"name": "rot", "management_cidrs": []string{"203.0.113.10/32"}})
	mustOK(t, "node", code, body, http.StatusCreated)
	var created struct {
		Node  NodeDTO `json:"node"`
		Token string  `json:"enrollment_token"`
	}
	_ = json.Unmarshal(body, &created)
	dir := t.TempDir()
	if err := agent.Enroll(context.Background(), agent.Config{PanelURL: tp.base, StateDir: dir}, created.Token, false); err != nil {
		t.Fatal(err)
	}
	cfg := agent.Config{PanelURL: tp.base, StateDir: dir, NftTable: "sentinel_shield", ManagementCIDRs: []string{"203.0.113.10/32"},
		HeartbeatSeconds: 30, DetectMillis: 1000, ApprovalTimeoutS: 900}
	e := &rotationEnv{tp: tp, nodeID: created.Node.ID, stateDir: dir, cfg: cfg, rules: &e2eRules{counters: map[string]nft.Counter{}}}
	e.ag = e.newAgent(t)
	return e
}

func (e *rotationEnv) newAgent(t *testing.T) *agent.Agent {
	t.Helper()
	client, err := agent.NewPanelClient(e.tp.base, "")
	if err != nil {
		t.Fatal(err)
	}
	a, err := agent.New(e.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), e.rules, nil, client)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func signedHeartbeatStatus(t *testing.T, base, nodeID string, priv []byte) int {
	t.Helper()
	body := []byte(`{"agent_version":"0.1.0","health":{"status":"ok"}}`)
	req, _ := http.NewRequest(http.MethodPost, base+"/agent/v1/heartbeat", bytes.NewReader(body))
	if err := identity.Sign(req, nodeID, priv, body, time.Now()); err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestKeyRotation(t *testing.T) {
	e := newRotationEnv(t)
	ctx := context.Background()
	if err := e.ag.Heartbeat(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	oldKey, err := identity.LoadKey(filepath.Join(e.stateDir, "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	// Without an administrator request the panel refuses a key change.
	client, _ := agent.NewPanelClient(e.tp.base, "")
	newPub, _, _ := identity.GenerateKey()
	var he *agent.HTTPError
	if err := client.RotateKey(ctx, e.nodeID, oldKey, newPub); !errors.As(err, &he) || he.Status != http.StatusConflict {
		t.Fatalf("Rotation ohne Anforderung muss 409 liefern: %v", err)
	}

	code, body := e.tp.admin.call(http.MethodPost, "/api/v1/nodes/"+e.nodeID+"/rotate-key", nil)
	mustOK(t, "rotation anfordern", code, body, http.StatusOK)
	if err := e.ag.Heartbeat(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	newKey, err := identity.LoadKey(filepath.Join(e.stateDir, "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(newKey, oldKey) {
		t.Fatal("Schlüsseldatei wurde nicht ersetzt")
	}
	if _, err := identity.LoadKey(filepath.Join(e.stateDir, "identity.key.next")); err == nil {
		t.Fatal("identity.key.next muss nach erfolgreicher Rotation entfernt sein")
	}
	if err := e.ag.Heartbeat(ctx, time.Now()); err != nil {
		t.Fatalf("Heartbeat mit neuem Schlüssel: %v", err)
	}
	if code := signedHeartbeatStatus(t, e.tp.base, e.nodeID, oldKey); code != http.StatusUnauthorized {
		t.Fatalf("alter Schlüssel muss abgelehnt werden, erhielt %d", code)
	}
}

// If the agent dies after the panel accepted the new key but before it promoted the file,
// the next start must recover by using the pending key.
func TestKeyRotationCrashRecovery(t *testing.T) {
	e := newRotationEnv(t)
	ctx := context.Background()
	oldKey, _ := identity.LoadKey(filepath.Join(e.stateDir, "identity.key"))
	code, body := e.tp.admin.call(http.MethodPost, "/api/v1/nodes/"+e.nodeID+"/rotate-key", nil)
	mustOK(t, "rotation anfordern", code, body, http.StatusOK)

	// Simulate the crash window: next key on disk, panel switched, no promotion.
	pub, priv, _ := identity.GenerateKey()
	if err := identity.SaveKey(filepath.Join(e.stateDir, "identity.key.next"), priv); err != nil {
		t.Fatal(err)
	}
	client, _ := agent.NewPanelClient(e.tp.base, "")
	if err := client.RotateKey(ctx, e.nodeID, oldKey, pub); err != nil {
		t.Fatal(err)
	}

	restarted := e.newAgent(t) // loads the stale identity.key
	if err := restarted.Heartbeat(ctx, time.Now()); err != nil {
		t.Fatalf("Neustart muss den ausstehenden Schlüssel übernehmen: %v", err)
	}
	got, _ := identity.LoadKey(filepath.Join(e.stateDir, "identity.key"))
	if !bytes.Equal(got, priv) {
		t.Fatal("der ausstehende Schlüssel muss zur Identität werden")
	}
}

// A malformed event must not block the heartbeat or the events that follow it.
func TestPoisonEventDoesNotBlockHeartbeat(t *testing.T) {
	e := newRotationEnv(t)
	priv, err := identity.LoadKey(filepath.Join(e.stateDir, "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	body := []byte(`{"agent_version":"0.1.0","health":{"status":"ok"},"events":[
	 {"id":"poison-1","type":"mitigation","action":"proposed_applied","at":"` + now + `","payload":{"id":"x","target":"","kind":"syn_rate_limit"}},
	 {"id":"unknown-1","type":"mitigation","action":"something_new","at":"` + now + `","payload":{"foo":1}},
	 {"id":"good-1","type":"alert","action":"escalation","at":"` + now + `","payload":{"incident_id":"inc-1","target":"192.0.2.1/32","category":"syn_flood","peak_pps":1,"note":"ok"}}]}`)
	req, _ := http.NewRequest(http.MethodPost, e.tp.base+"/agent/v1/heartbeat", bytes.NewReader(body))
	if err := identity.Sign(req, e.nodeID, priv, body, time.Now()); err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ein fehlerhaftes Ereignis darf den Heartbeat nicht scheitern lassen: HTTP %d", resp.StatusCode)
	}
	code, out := e.tp.admin.call(http.MethodGet, "/api/v1/alerts", nil)
	mustOK(t, "alarme", code, out, http.StatusOK)
	if !bytes.Contains(out, []byte("Eskalation")) {
		t.Fatalf("das gültige Ereignis nach dem fehlerhaften muss verarbeitet werden: %s", out)
	}
}
