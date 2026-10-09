package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vaktikos/ddos-prot/internal/mcguard"
	"github.com/vaktikos/ddos-prot/internal/policy"
)

type fakeGuard struct {
	mu  sync.Mutex
	v   mcguard.StatsView
	srv *httptest.Server
}

func newFakeGuard(t *testing.T) *fakeGuard {
	g := &fakeGuard{}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		_ = json.NewEncoder(w).Encode(g.v)
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGuard) update(f func(v *mcguard.StatsView)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	f(&g.v)
}

func guardPolicy(version int64, mode string) *policy.Policy {
	p := xdpPolicy(version, mode)
	prof := p.Profiles["std"]
	prof.ProtocolAbusePPS = 50
	p.Profiles["std"] = prof
	return p
}

func guardAgent(t *testing.T, mode string) (*Agent, *fakeGuard, *fakeXDP, *driver, *testEnv) {
	e := setupEnv(t)
	g := newFakeGuard(t)
	e.cfg.MinecraftGuards = []GuardConfig{{Name: "mc", StatsURL: g.srv.URL + "/stats", Target: "192.0.2.10/32"}}
	e.panel.publish(t, guardPolicy(1, mode))
	a := e.newAgent(t)
	x := newFakeXDP()
	a.SetXDP(x)
	_ = a.Heartbeat(t.Context(), time.Now())
	return a, g, x, &driver{t: t, a: a, rules: e.rules, now: time.Now()}, e
}

func TestGuardProtocolAbuseOpensIncidentAndBansAreMirrored(t *testing.T) {
	a, g, x, d, _ := guardAgent(t, policy.ModeAuto)
	d.quiet(6)
	d.now = d.now.Add(0)
	until := d.now.Add(10 * time.Minute)
	g.update(func(v *mcguard.StatsView) {
		v.Bans = []mcguard.Ban{
			{Addr: "1.2.3.4", Until: until},
			{Addr: "203.0.113.10", Until: until}, // management
			{Addr: "192.0.2.10", Until: until},   // protected
			{Addr: "198.51.100.9", Until: until}, // trusted
		}
	})
	for i := 0; i < 12; i++ {
		g.update(func(v *mcguard.StatsView) { v.Accepted += 400; v.Invalid += 400 })
		d.quiet(1)
	}
	if _, ok := x.blocks[netip.MustParsePrefix("1.2.3.4/32")]; !ok {
		t.Fatalf("Guard-Sperre muss in XDP gespiegelt werden: %v", x.blocks)
	}
	if len(x.blocks) != 1 {
		t.Fatalf("Management/geschützte/vertrauenswürdige Adressen dürfen nie gesperrt werden: %v", x.blocks)
	}
	if !strings.Contains(strings.Join(outboxTypes(a), " "), "incident/") {
		t.Fatalf("Protokollmissbrauch muss einen Vorfall öffnen: %v", outboxTypes(a))
	}
	reps := a.guardReports()
	if len(reps) != 1 || !reps[0].Reachable || reps[0].InvalidPS < 100 || reps[0].Bans != 4 {
		t.Fatalf("Guard-Bericht falsch: %+v", reps)
	}
}

func TestGuardBansAreNotMirroredInDryRun(t *testing.T) {
	_, g, x, d, _ := guardAgent(t, policy.ModeDryRun)
	until := d.now.Add(10 * time.Minute)
	g.update(func(v *mcguard.StatsView) { v.Bans = []mcguard.Ban{{Addr: "1.2.3.4", Until: until}} })
	d.quiet(6)
	if len(x.blocks) != 0 {
		t.Fatalf("Dry-Run darf nichts sperren: %v", x.blocks)
	}
}

func TestUnreachableGuardIsReportedAndDoesNotBreakTicks(t *testing.T) {
	a, g, _, d, _ := guardAgent(t, policy.ModeAuto)
	g.srv.Close()
	d.quiet(6)
	reps := a.guardReports()
	if len(reps) != 1 || reps[0].Reachable {
		t.Fatalf("unerreichbarer Guard muss als solcher gemeldet werden: %+v", reps)
	}
	if h := a.health(); h.Status != "degraded" {
		t.Fatalf("Gesundheit muss degraded sein: %+v", h)
	}
}

func TestGuardConfigMustBeLoopback(t *testing.T) {
	bad := []GuardConfig{{Name: "x", StatsURL: "http://10.0.0.5:9199/stats", Target: "192.0.2.10/32"}}
	if validateGuards(bad) == nil {
		t.Fatal("Nicht-Loopback-Adresse muss abgelehnt werden")
	}
	good := []GuardConfig{{Name: "x", StatsURL: "http://127.0.0.1:9199/stats", Target: "192.0.2.10/32"}}
	if err := validateGuards(good); err != nil {
		t.Fatal(err)
	}
}
