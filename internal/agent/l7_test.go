package agent

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vaktikos/ddos-prot/internal/policy"
)

func l7Policy(version int64, mode string) *policy.Policy {
	p := xdpPolicy(version, mode)
	prof := p.Profiles["std"]
	prof.HTTPRejectRPS = 100
	prof.Mitigation.L7SourceRPS = 30
	prof.Mitigation.L7BlockSeconds = 120
	p.Profiles["std"] = prof
	return p
}

func l7Agent(t *testing.T, mode string) (*Agent, string, *fakeXDP, *driver) {
	e := setupEnv(t)
	logPath := filepath.Join(t.TempDir(), "ss_reject.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	e.cfg.L7Sources = []L7Config{{Name: "web", Path: logPath, Target: "192.0.2.10/32"}}
	e.panel.publish(t, l7Policy(1, mode))
	a := e.newAgent(t)
	x := newFakeXDP()
	a.SetXDP(x)
	_ = a.Heartbeat(t.Context(), time.Now())
	return a, logPath, x, &driver{t: t, a: a, rules: e.rules, now: time.Now()}
}

func appendRejects(t *testing.T, path, addr string, n int) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "%s [2026-10-09T12:00:00+00:00] \"GET /login HTTP/1.1\" 429 limit=REJECTED ua=\"x\"\n", addr)
	}
	f.WriteString(b.String())
}

func TestL7FloodOpensIncidentAndBlocksOnlyStrongSources(t *testing.T) {
	a, path, x, d := l7Agent(t, policy.ModeAuto)
	d.quiet(3)
	for i := 0; i < 10; i++ {
		appendRejects(t, path, "1.2.3.4", 120)
		appendRejects(t, path, "5.6.7.8", 3)        // weak source
		appendRejects(t, path, "203.0.113.10", 200) // management
		appendRejects(t, path, "198.51.100.9", 200) // trusted
		appendRejects(t, path, "192.0.2.10", 200)   // protected address
		d.quiet(1)
	}
	if _, ok := x.blocks[netip.MustParsePrefix("1.2.3.4/32")]; !ok {
		t.Fatalf("starke Quelle muss gesperrt werden: %v (%v)", x.blocks, outboxTypes(a))
	}
	if len(x.blocks) != 1 {
		t.Fatalf("schwache, Management-, vertrauenswürdige und geschützte Adressen nie sperren: %v", x.blocks)
	}
	if !strings.Contains(strings.Join(outboxTypes(a), " "), "mitigation/l7_blocked") {
		t.Fatalf("Sperre muss gemeldet werden: %v", outboxTypes(a))
	}
	r := a.l7Reports()
	if len(r) != 1 || !r[0].Readable || len(r[0].Top) == 0 || r[0].Top[0].Addr == "" || r[0].Blocked != 1 {
		t.Fatalf("Bericht: %+v", r)
	}
}

func TestL7NothingIsBlockedInDryRun(t *testing.T) {
	_, path, x, d := l7Agent(t, policy.ModeDryRun)
	d.quiet(3)
	for i := 0; i < 10; i++ {
		appendRejects(t, path, "1.2.3.4", 500)
		d.quiet(1)
	}
	if len(x.blocks) != 0 {
		t.Fatalf("Dry-Run darf nichts sperren: %v", x.blocks)
	}
}

func TestL7MissingLogIsReported(t *testing.T) {
	a, path, _, d := l7Agent(t, policy.ModeAuto)
	os.Remove(path)
	d.quiet(3)
	if r := a.l7Reports(); len(r) != 1 || r[0].Readable {
		t.Fatalf("fehlende Datei muss gemeldet werden: %+v", r)
	}
	if h := a.health(); h.Status != "degraded" {
		t.Fatalf("Gesundheit: %+v", h)
	}
}

func TestL7ConfigValidation(t *testing.T) {
	if validateL7([]L7Config{{Name: "a", Path: "relative.log", Target: "192.0.2.10/32"}}) == nil {
		t.Fatal("relativer Pfad muss abgelehnt werden")
	}
	if validateL7([]L7Config{{Name: "a", Path: "/var/log/x.log", Target: "nonsense"}}) == nil {
		t.Fatal("ungültiges Ziel muss abgelehnt werden")
	}
	if err := validateL7([]L7Config{{Name: "a", Path: "/var/log/x.log", Target: "192.0.2.10/32"}}); err != nil {
		t.Fatal(err)
	}
}
