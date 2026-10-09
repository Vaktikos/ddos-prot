package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vaktikos/ddos-prot/internal/identity"
	"github.com/vaktikos/ddos-prot/internal/mitigate"
	"github.com/vaktikos/ddos-prot/internal/nft"
	"github.com/vaktikos/ddos-prot/internal/policy"
)

// fakeRules replaces the kernel. It records every applied script and exposes counters.
type fakeRules struct {
	mu        sync.Mutex
	applied   []string
	counters  map[string]nft.Counter
	installed bool
	failApply bool
}

func (f *fakeRules) Apply(script string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failApply {
		return errors.New("kernel lehnt Ruleset ab")
	}
	f.applied = append(f.applied, script)
	f.installed = true
	return nil
}

func (f *fakeRules) Counters() (map[string]nft.Counter, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]nft.Counter{}
	for k, v := range f.counters {
		out[k] = v
	}
	return out, nil
}

func (f *fakeRules) SetSize(string) (int, error) { return 0, nil }
func (f *fakeRules) Installed() bool             { return f.installed }

func (f *fakeRules) add(name string, pkts uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.counters[name]
	c.Packets += pkts
	c.Bytes += pkts * 100
	f.counters[name] = c
}

func (f *fakeRules) lastScript() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.applied) == 0 {
		return ""
	}
	return f.applied[len(f.applied)-1]
}

// fakePanel serves signed envelopes and records heartbeats.
type fakePanel struct {
	mu         sync.Mutex
	priv       ed25519.PrivateKey
	env        policy.Envelope
	reply      HeartbeatReply
	heartbeats []Heartbeat
	srv        *httptest.Server
}

func newFakePanel(t *testing.T, priv ed25519.PrivateKey) *fakePanel {
	fp := &fakePanel{priv: priv}
	fp.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fp.mu.Lock()
		defer fp.mu.Unlock()
		switch r.URL.Path {
		case "/agent/v1/heartbeat":
			body, _ := io.ReadAll(r.Body)
			var hb Heartbeat
			if err := json.Unmarshal(body, &hb); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			fp.heartbeats = append(fp.heartbeats, hb)
			_ = json.NewEncoder(w).Encode(fp.reply)
		case "/agent/v1/policy":
			_ = json.NewEncoder(w).Encode(fp.env)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fp.srv.Close)
	return fp
}

func (fp *fakePanel) publish(t *testing.T, p *policy.Policy) {
	t.Helper()
	env, err := policy.Sign(fp.priv, p)
	if err != nil {
		t.Fatal(err)
	}
	fp.mu.Lock()
	fp.env = env
	fp.reply.DesiredPolicyVersion = p.Version
	fp.mu.Unlock()
}

func (fp *fakePanel) setApproval(ids ...string) {
	fp.mu.Lock()
	fp.reply.ApprovedPlanIDs = ids
	fp.mu.Unlock()
}

func (fp *fakePanel) lastHeartbeat() Heartbeat {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	return fp.heartbeats[len(fp.heartbeats)-1]
}

type testEnv struct {
	dir      string
	panelPub ed25519.PublicKey
	panelKey ed25519.PrivateKey
	panel    *fakePanel
	rules    *fakeRules
	cfg      Config
}

func setupEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	panelPub, panelKey, _ := ed25519.GenerateKey(nil)
	agentPub, agentPriv, _ := identity.GenerateKey()
	_ = agentPub
	if err := identity.SaveKey(dir+"/identity.key", agentPriv); err != nil {
		t.Fatal(err)
	}
	if err := (Store{Dir: dir}).SaveNode(NodeFile{NodeID: "node-1", PanelPublicKey: base64.StdEncoding.EncodeToString(panelPub)}); err != nil {
		t.Fatal(err)
	}
	cfg := Config{PanelURL: "", StateDir: dir, NftTable: "sentinel_shield", ManagementCIDRs: []string{"203.0.113.10/32"},
		HeartbeatSeconds: 30, DetectMillis: 1000, ApprovalTimeoutS: 900}
	cfg.applyDefaults()
	fp := newFakePanel(t, panelKey)
	cfg.PanelURL = fp.srv.URL
	return &testEnv{dir: dir, panelPub: panelPub, panelKey: panelKey, panel: fp,
		rules: &fakeRules{counters: map[string]nft.Counter{}}, cfg: cfg}
}

func (e *testEnv) newAgent(t *testing.T) *Agent {
	t.Helper()
	client, err := NewPanelClient(e.cfg.PanelURL, "")
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(e.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), e.rules, nil, client)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func testPolicy(version int64, mode string) *policy.Policy {
	return &policy.Policy{
		Version: version, NodeID: "node-1", Mode: mode, IssuedAt: time.Now(),
		Targets: []policy.Target{{Name: "web", Prefix: "192.0.2.10/32", Profile: "std",
			Services: []policy.Service{{Name: "https", Protocol: policy.ProtoTCP, Port: 443}}}},
		Profiles: map[string]policy.Profile{"std": {
			Kind: "generic", SYNPPS: 20000, TotalPPS: 100000, ConfirmSeconds: 3, ClearSeconds: 5,
			Mitigation: policy.Mitigation{SYNRatePerSource: 100, AutoBlockSeconds: 300},
		}},
		Limits: policy.Limits{MaxActiveBlocks: 100, MaxDynamicEntries: 1000},
	}
}

// driver feeds one-second counter steps into the agent, like the kernel would.
type driver struct {
	t     *testing.T
	a     *Agent
	rules *fakeRules
	now   time.Time
}

func (d *driver) second(pkts, syn uint64) {
	d.rules.add("t0_all", pkts)
	d.rules.add("t0_syn", syn)
	d.now = d.now.Add(time.Second)
	d.a.Tick(d.now)
}

func (d *driver) quiet(n int) {
	for i := 0; i < n; i++ {
		d.second(1000, 10)
	}
}

func (d *driver) attack(n int) {
	for i := 0; i < n; i++ {
		d.second(60000, 50000)
	}
}

func outboxTypes(a *Agent) []string {
	var out []string
	for _, e := range a.outbox {
		out = append(out, e.Type+"/"+e.Action)
	}
	return out
}

func TestDryRunProposesButNeverTouchesFirewall(t *testing.T) {
	e := setupEnv(t)
	e.panel.publish(t, testPolicy(1, policy.ModeDryRun))
	a := e.newAgent(t)
	if err := a.Heartbeat(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if a.applied != 1 {
		t.Fatalf("Policy v1 nicht angewendet (applied=%d, err=%q)", a.applied, a.policyErr)
	}
	before := len(e.rules.applied)

	d := &driver{t: t, a: a, rules: e.rules, now: time.Now()}
	d.quiet(5)
	d.attack(6)

	if len(a.plans) != 1 || a.plans[0].Status != mitigate.StatusProposed || !a.plans[0].DryRun {
		t.Fatalf("erwartet ein Dry-Run-Vorschlag, erhalten %+v", a.plans)
	}
	if len(e.rules.applied) != before {
		t.Fatal("Dry-Run darf keine zusätzliche Firewall-Änderung anwenden")
	}
	if !strings.Contains(strings.Join(outboxTypes(a), " "), "incident/escalated") {
		t.Fatalf("Eskalation fehlt im Outbox: %v", outboxTypes(a))
	}
}

func TestAutoModeAppliesIncidentBoundMitigationAndRemovesIt(t *testing.T) {
	e := setupEnv(t)
	e.panel.publish(t, testPolicy(2, policy.ModeAuto))
	a := e.newAgent(t)
	_ = a.Heartbeat(context.Background(), time.Now())
	d := &driver{t: t, a: a, rules: e.rules, now: time.Now()}
	d.quiet(5)
	d.attack(6)

	if !strings.Contains(e.rules.lastScript(), `meter ss_t0_tcp443`) {
		t.Fatalf("Ratenlimit wurde im Auto-Modus nicht angewendet:\n%s", e.rules.lastScript())
	}
	if !strings.Contains(e.rules.lastScript(), `comment "`) {
		t.Fatal("Maßnahme muss einem Vorfall zugeordnet sein (comment fehlt)")
	}

	d.quiet(10) // incident clears after ClearSeconds
	if strings.Contains(e.rules.lastScript(), "meter ss_") {
		t.Fatal("nach Ende des Vorfalls muss die Ratenregel zurückgenommen sein")
	}
	if len(a.plans) != 0 {
		t.Fatalf("Maßnahmen-Liste muss nach Vorfallende leer sein: %+v", a.plans)
	}
}

func TestApprovalModeWaitsForOperator(t *testing.T) {
	e := setupEnv(t)
	e.panel.publish(t, testPolicy(3, policy.ModeApproval))
	a := e.newAgent(t)
	_ = a.Heartbeat(context.Background(), time.Now())
	d := &driver{t: t, a: a, rules: e.rules, now: time.Now()}
	d.quiet(5)
	d.attack(6)
	if strings.Contains(e.rules.lastScript(), "meter ss_") {
		t.Fatal("ohne Freigabe darf keine Maßnahme aktiv sein")
	}
	if len(a.plans) != 1 || a.plans[0].Status != mitigate.StatusPendingApproval {
		t.Fatalf("erwartet wartende Freigabe: %+v", a.plans)
	}
	planID := a.plans[0].ID

	e.panel.setApproval(planID)
	_ = a.Heartbeat(context.Background(), d.now)
	if !strings.Contains(e.rules.lastScript(), "meter ss_t0_tcp443") {
		t.Fatal("freigegebene Maßnahme muss angewendet werden")
	}
}

func TestPanelOutageKeepsDetectionAndCachedPolicy(t *testing.T) {
	e := setupEnv(t)
	e.panel.publish(t, testPolicy(4, policy.ModeAuto))
	a := e.newAgent(t)
	_ = a.Heartbeat(context.Background(), time.Now())
	d := &driver{t: t, a: a, rules: e.rules, now: time.Now()}
	d.quiet(3)

	e.panel.srv.Close() // control plane goes away

	if err := a.Heartbeat(context.Background(), d.now); err == nil {
		t.Fatal("Heartbeat ohne Panel muss einen Fehler liefern")
	}
	d.attack(6)
	if !strings.Contains(e.rules.lastScript(), "meter ss_t0_tcp443") {
		t.Fatal("bei Panel-Ausfall muss die lokale Erkennung und Mitigation weiterlaufen")
	}

	// A restarted agent with no panel reachable adopts the cached, signed policy.
	restarted := e.newAgent(t)
	restarted.Bootstrap()
	if restarted.applied != 4 {
		t.Fatalf("gecachte Policy nicht übernommen: applied=%d err=%q", restarted.applied, restarted.policyErr)
	}
}

func TestTamperedPolicyIsRejectedAndPreviousKept(t *testing.T) {
	e := setupEnv(t)
	e.panel.publish(t, testPolicy(5, policy.ModeDryRun))
	a := e.newAgent(t)
	_ = a.Heartbeat(context.Background(), time.Now())
	if a.applied != 5 {
		t.Fatalf("Ausgangszustand fehlt: %d", a.applied)
	}

	// The panel is compromised or the transport tampered: body changed, signature kept.
	bad := testPolicy(6, policy.ModeAuto)
	env, _ := policy.Sign(e.panelKey, bad)
	env.Body = strings.Replace(env.Body, `"mode":"auto"`, `"mode":"dry_run"`, 1)
	e.panel.mu.Lock()
	e.panel.env = env
	e.panel.reply.DesiredPolicyVersion = 6
	e.panel.mu.Unlock()

	_ = a.Heartbeat(context.Background(), time.Now())
	if a.applied != 5 {
		t.Fatalf("manipulierte Policy darf nicht übernommen werden (applied=%d)", a.applied)
	}
	if a.policyErr == "" {
		t.Fatal("abgelehnte Policy muss als Fehler sichtbar sein")
	}
}

func TestKernelFailureRetainsPreviousRuleset(t *testing.T) {
	e := setupEnv(t)
	e.panel.publish(t, testPolicy(7, policy.ModeDryRun))
	a := e.newAgent(t)
	e.rules.failApply = true
	_ = a.Heartbeat(context.Background(), time.Now())
	if a.applied != 0 {
		t.Fatal("fehlgeschlagene Anwendung darf nicht als angewendet gelten")
	}
	if a.pol != nil {
		t.Fatal("fehlgeschlagene Anwendung muss den vorherigen Zustand (hier: keinen) wiederherstellen")
	}
	if !strings.Contains(a.policyErr, "kernel") {
		t.Fatalf("Fehler nicht gemeldet: %q", a.policyErr)
	}
}

func TestHeartbeatCarriesHealthAndDeliversOutbox(t *testing.T) {
	e := setupEnv(t)
	e.panel.publish(t, testPolicy(8, policy.ModeDryRun))
	a := e.newAgent(t)
	_ = a.Heartbeat(context.Background(), time.Now())
	d := &driver{t: t, a: a, rules: e.rules, now: time.Now()}
	d.quiet(3)
	d.attack(5)
	pending := len(a.outbox)
	if pending == 0 {
		t.Fatal("Ereignisse müssen im Outbox liegen")
	}
	_ = a.Heartbeat(context.Background(), d.now)
	hb := e.panel.lastHeartbeat()
	if len(hb.Events) != pending {
		t.Fatalf("Heartbeat transportiert %d Ereignisse, erwartet %d", len(hb.Events), pending)
	}
	if len(a.outbox) != 0 {
		t.Fatal("bestätigte Ereignisse müssen aus dem Outbox entfernt werden")
	}
	if hb.Health.Status != "ok" || hb.AppliedPolicyVersion != 8 {
		t.Fatalf("Health/Version falsch: %+v", hb.Health)
	}
}

func TestOutboxIsBoundedDuringOutage(t *testing.T) {
	e := setupEnv(t)
	e.panel.publish(t, testPolicy(9, policy.ModeDryRun))
	a := e.newAgent(t)
	_ = a.Heartbeat(context.Background(), time.Now())
	before := len(a.outbox)
	for i := 0; i < maxOutbox+50; i++ {
		a.emit("alert", "test", i)
	}
	wantDropped := uint64(before + 50)
	if len(a.outbox) != maxOutbox || a.dropped != wantDropped {
		t.Fatalf("Outbox nicht begrenzt: len=%d dropped=%d want=%d", len(a.outbox), a.dropped, wantDropped)
	}
}

func TestPanelClientRequiresHTTPSExceptLoopback(t *testing.T) {
	if _, err := NewPanelClient("http://panel.example.com", ""); err == nil {
		t.Fatal("unverschlüsseltes http außerhalb von localhost darf nicht erlaubt sein")
	}
	if _, err := NewPanelClient("https://panel.example.com", ""); err != nil {
		t.Fatal(err)
	}
}

func TestConfigRequiresManagementNetwork(t *testing.T) {
	c := Config{PanelURL: "https://panel.example.com", HeartbeatSeconds: 30, DetectMillis: 1000, ApprovalTimeoutS: 900}
	if err := c.Validate(); err == nil {
		t.Fatal("ohne management_cidrs darf die Konfiguration nicht gültig sein")
	}
	c.ManagementCIDRs = []string{"203.0.113.10/32"}
	if err := c.Validate(); err != nil {
		t.Fatalf("gültige Konfiguration abgelehnt: %v", err)
	}
}

func TestRemovingTargetClosesIncidentAndMitigation(t *testing.T) {
	e := setupEnv(t)
	e.panel.publish(t, testPolicy(1, policy.ModeAuto))
	a := e.newAgent(t)
	_ = a.Heartbeat(context.Background(), time.Now())
	d := &driver{t: t, a: a, rules: e.rules, now: time.Now()}
	d.quiet(5)
	d.attack(6)
	if !strings.Contains(e.rules.lastScript(), "meter ss_t0_tcp443") {
		t.Fatal("Vorbedingung: Mitigation muss aktiv sein")
	}
	// Version 2 protects a different address only.
	p2 := testPolicy(2, policy.ModeAuto)
	p2.Targets[0].Prefix = "192.0.2.77/32"
	e.panel.publish(t, p2)
	_ = a.Heartbeat(context.Background(), d.now)
	if a.applied != 2 {
		t.Fatalf("neue Policy nicht angewendet: applied=%d err=%q", a.applied, a.policyErr)
	}
	if strings.Contains(e.rules.lastScript(), "meter ss_") || len(a.plans) != 0 {
		t.Fatal("Mitigation des entfernten Ziels muss verschwinden")
	}
	if _, active := a.engine.Active("192.0.2.10/32"); active {
		t.Fatal("Erkennungszustand des entfernten Ziels muss verworfen sein")
	}
}

func TestOlderSignedPolicyIsRejected(t *testing.T) {
	e := setupEnv(t)
	e.panel.publish(t, testPolicy(5, policy.ModeDryRun))
	a := e.newAgent(t)
	_ = a.Heartbeat(context.Background(), time.Now())
	if a.applied != 5 {
		t.Fatal("Ausgangszustand fehlt")
	}
	// Replay of a validly signed but older envelope while the reply claims a newer version.
	old, _ := policy.Sign(e.panelKey, testPolicy(3, policy.ModeAuto))
	e.panel.mu.Lock()
	e.panel.env = old
	e.panel.reply.DesiredPolicyVersion = 6
	e.panel.mu.Unlock()
	_ = a.Heartbeat(context.Background(), time.Now())
	if a.applied != 5 || a.pol.Mode != policy.ModeDryRun {
		t.Fatalf("alte Policy wurde übernommen: applied=%d mode=%s", a.applied, a.pol.Mode)
	}
}

func TestRejectedPolicyIsNotCached(t *testing.T) {
	e := setupEnv(t)
	e.panel.publish(t, testPolicy(1, policy.ModeDryRun))
	e.rules.failApply = true
	a := e.newAgent(t)
	_ = a.Heartbeat(context.Background(), time.Now())
	if env, _ := (Store{Dir: e.dir}).LoadEnvelope(); env != nil {
		t.Fatal("eine vom Kernel abgelehnte Policy darf nicht im Cache landen")
	}
}

func TestNearlyFullConntrackTableDegradesHealth(t *testing.T) {
	e := setupEnv(t)
	e.panel.publish(t, testPolicy(1, policy.ModeDryRun))
	client, _ := NewPanelClient(e.cfg.PanelURL, "")
	count := uint64(100)
	host := func() (HostCounters, error) {
		return HostCounters{ConntrackCount: count, ConntrackMax: 1000}, nil
	}
	a, err := New(e.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), e.rules, host, client)
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Heartbeat(context.Background(), time.Now())
	now := time.Now()
	a.Tick(now)
	count = 900
	a.Tick(now.Add(time.Second))
	h := a.health()
	if h.Status != "degraded" || !strings.Contains(strings.Join(h.Errors, " "), "conntrack") {
		t.Fatalf("90 %% conntrack muss degraded melden: %+v", h)
	}
}

// fakeXDP records what the agent asks the filter to do.
type fakeXDP struct {
	allow, protect []netip.Prefix
	manual         map[netip.Prefix]time.Time
	blocks         map[netip.Prefix]time.Time
	rates          []SourceRate
	resets         int
}

func newFakeXDP() *fakeXDP {
	return &fakeXDP{manual: map[netip.Prefix]time.Time{}, blocks: map[netip.Prefix]time.Time{}}
}
func (f *fakeXDP) SetAllow(p []netip.Prefix) error     { f.allow = p; return nil }
func (f *fakeXDP) SetProtected(p []netip.Prefix) error { f.protect = p; return nil }
func (f *fakeXDP) SetBlocks(_ string, w map[netip.Prefix]time.Time) error {
	f.manual = w
	return nil
}
func (f *fakeXDP) Block(p netip.Prefix, until time.Time, _ string) error {
	f.blocks[p] = until
	return nil
}
func (f *fakeXDP) Expire(time.Time) int { return 0 }
func (f *fakeXDP) BlockCount() int      { return len(f.blocks) }
func (f *fakeXDP) Sample(time.Time, float64, int) []SourceRate {
	return f.rates
}
func (f *fakeXDP) ResetBaseline()           { f.resets++ }
func (f *fakeXDP) Stats() (XDPStats, error) { return XDPStats{}, nil }

func xdpPolicy(version int64, mode string) *policy.Policy {
	p := testPolicy(version, mode)
	prof := p.Profiles["std"]
	prof.Mitigation.XDPSourcePPS = 1000
	prof.Mitigation.XDPBlockSeconds = 60
	p.Profiles["std"] = prof
	p.Trusted = []string{"198.51.100.0/24"}
	p.Blocks = []policy.ManualBlock{{RuleID: "r1", Prefix: "203.0.113.99/32", ExpiresAt: time.Now().Add(time.Hour)}}
	return p
}

func TestXDPBlocksStrongSourcesButNeverProtectedAddresses(t *testing.T) {
	e := setupEnv(t)
	e.panel.publish(t, xdpPolicy(1, policy.ModeAuto))
	a := e.newAgent(t)
	x := newFakeXDP()
	a.SetXDP(x)
	_ = a.Heartbeat(context.Background(), time.Now())

	if len(x.allow) < 2 || len(x.protect) != 1 || len(x.manual) != 1 {
		t.Fatalf("Policy nicht gespiegelt: allow=%v protect=%v manual=%v", x.allow, x.protect, x.manual)
	}

	d := &driver{t: t, a: a, rules: e.rules, now: time.Now()}
	d.quiet(5)
	x.rates = []SourceRate{
		{Addr: netip.MustParseAddr("1.2.3.4"), PPS: 5000},
		{Addr: netip.MustParseAddr("203.0.113.10"), PPS: 9000}, // management
		{Addr: netip.MustParseAddr("192.0.2.10"), PPS: 8000},   // the protected address itself
		{Addr: netip.MustParseAddr("198.51.100.7"), PPS: 7000}, // trusted network
	}
	d.attack(8)

	if _, ok := x.blocks[netip.MustParsePrefix("1.2.3.4/32")]; !ok {
		t.Fatalf("starke Quelle muss gesperrt werden: %v", x.blocks)
	}
	if len(x.blocks) != 1 {
		t.Fatalf("Management, geschützte und vertrauenswürdige Adressen dürfen nie gesperrt werden: %v", x.blocks)
	}
	if x.resets == 0 {
		t.Fatal("beim Start des Quellsperrens muss die Basislinie zurückgesetzt werden")
	}
}

func TestXDPIsNotUsedInDryRun(t *testing.T) {
	e := setupEnv(t)
	e.panel.publish(t, xdpPolicy(1, policy.ModeDryRun))
	a := e.newAgent(t)
	x := newFakeXDP()
	a.SetXDP(x)
	_ = a.Heartbeat(context.Background(), time.Now())
	d := &driver{t: t, a: a, rules: e.rules, now: time.Now()}
	d.quiet(5)
	x.rates = []SourceRate{{Addr: netip.MustParseAddr("1.2.3.4"), PPS: 5000}}
	d.attack(8)
	if len(x.blocks) != 0 {
		t.Fatalf("Dry-Run darf nichts sperren: %v", x.blocks)
	}
}

func TestMissingXDPIsReportedNotSilentlyIgnored(t *testing.T) {
	e := setupEnv(t)
	e.panel.publish(t, xdpPolicy(1, policy.ModeAuto))
	a := e.newAgent(t) // no XDP enabled
	_ = a.Heartbeat(context.Background(), time.Now())
	d := &driver{t: t, a: a, rules: e.rules, now: time.Now()}
	d.quiet(5)
	d.attack(8)
	if !strings.Contains(strings.Join(outboxTypes(a), " "), "mitigation/xdp_unavailable") {
		t.Fatalf("fehlendes XDP muss gemeldet werden: %v", outboxTypes(a))
	}
	if !strings.Contains(e.rules.lastScript(), "meter ss_") {
		t.Fatal("die nftables-Maßnahme muss trotzdem greifen")
	}
}

func TestXDPNeverBlocksThePanelAddress(t *testing.T) {
	e := setupEnv(t) // the fake panel listens on 127.0.0.1
	e.panel.publish(t, xdpPolicy(1, policy.ModeAuto))
	a := e.newAgent(t)
	x := newFakeXDP()
	a.SetXDP(x)
	_ = a.Heartbeat(context.Background(), time.Now())
	d := &driver{t: t, a: a, rules: e.rules, now: time.Now()}
	d.quiet(5)
	x.rates = []SourceRate{{Addr: netip.MustParseAddr("127.0.0.1"), PPS: 9000}, {Addr: netip.MustParseAddr("1.2.3.4"), PPS: 5000}}
	d.attack(8)
	if _, bad := x.blocks[netip.MustParsePrefix("127.0.0.1/32")]; bad {
		t.Fatal("die Panel-Adresse darf nie gesperrt werden")
	}
	if _, ok := x.blocks[netip.MustParsePrefix("1.2.3.4/32")]; !ok {
		t.Fatal("andere starke Quellen müssen weiterhin gesperrt werden")
	}
	found := false
	for _, p := range x.allow {
		if p.Contains(netip.MustParseAddr("127.0.0.1")) {
			found = true
		}
	}
	if !found {
		t.Fatalf("Panel-Adresse muss in der Allowlist stehen: %v", x.allow)
	}
}
