package nft

import (
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/vaktikos/ddos-prot/internal/policy"
)

var now = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func testPolicy() *policy.Policy {
	return &policy.Policy{
		Version: 2, NodeID: "n1", Mode: policy.ModeAuto,
		Targets: []policy.Target{
			{Name: "web", Prefix: "192.0.2.10/32", Profile: "std", Services: []policy.Service{
				{Name: "https", Protocol: policy.ProtoTCP, Port: 443},
				{Name: "dns", Protocol: policy.ProtoUDP, Port: 53},
			}},
			{Name: "v6", Prefix: "2001:db8:1::10/128", Profile: "std"},
		},
		Profiles: map[string]policy.Profile{"std": {
			Kind: "generic", SYNPPS: 20000, ConfirmSeconds: 5, ClearSeconds: 30,
			Mitigation: policy.Mitigation{SYNRatePerSource: 100, UDPRatePerSource: 500, AutoBlockSeconds: 300},
		}},
		Trusted: []string{"198.51.100.0/24"},
		Blocks: []policy.ManualBlock{
			{RuleID: "r1", Prefix: "203.0.113.5/32", ExpiresAt: now.Add(time.Hour)},
			{RuleID: "r2", Prefix: "2001:db8:bad::/48", ExpiresAt: now.Add(-time.Minute)},
		},
		Limits: policy.Limits{MaxActiveBlocks: 10, MaxDynamicEntries: 2048},
	}
}

var mgmt = []netip.Prefix{netip.MustParsePrefix("192.0.2.200/32")}

// activeMitigations is what the agent holds while incident inc-1 is confirmed.
func activeMitigations() []Active {
	return []Active{
		{ID: "inc1-syn", IncidentID: "inc1", Kind: KindSYNRate, Target: netip.MustParsePrefix("192.0.2.10/32"), Rate: 100, AutoBlockSeconds: 300},
		{ID: "inc1-udp", IncidentID: "inc1", Kind: KindUDPRate, Target: netip.MustParsePrefix("192.0.2.10/32"), Rate: 500},
		{ID: "inc2-udp", IncidentID: "inc2", Kind: KindUDPRate, Target: netip.MustParsePrefix("2001:db8:1::10/128"), Rate: 300, AutoBlockSeconds: 60},
	}
}

func TestRenderContainsRequiredRules(t *testing.T) {
	out, err := Render(testPolicy(), mgmt, now, DefaultTable, activeMitigations())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContain := []string{
		"add table inet sentinel_shield",
		"delete table inet sentinel_shield",
		"ip saddr @trusted4 accept",
		"ip saddr @mgmt4 accept",
		"ip daddr 192.0.2.10/32 tcp dport 443 tcp flags & (syn | ack) == syn meter ss_t0_tcp443",
		"add @dyn4 { ip saddr timeout 300s }",
		"ip6 daddr 2001:db8:1::10/128 meta l4proto udp meter",
		"add @dyn6 { ip6 saddr timeout 60s }",
		"set blk4 { type ipv4_addr; flags interval,timeout; elements = { 203.0.113.5/32 timeout 3600s",
		"counter name \"t0_syn\"",
		"counter name \"t0_s0_pkts\"",
	}
	for _, want := range mustContain {
		if !strings.Contains(out, want) {
			t.Errorf("Ruleset fehlt %q\n%s", want, out)
		}
	}
}

func TestNoMitigationWithoutIncident(t *testing.T) {
	out, err := Render(testPolicy(), mgmt, now, DefaultTable, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "meter ss_") {
		t.Fatal("ohne aktiven Vorfall darf keine Ratenlimit-Regel bestehen")
	}
}

func TestMitigationRefusesUnknownTarget(t *testing.T) {
	bad := []Active{{ID: "x", IncidentID: "inc", Kind: KindSYNRate, Target: netip.MustParsePrefix("192.0.2.99/32"), Rate: 10}}
	if _, err := Render(testPolicy(), mgmt, now, DefaultTable, bad); err == nil {
		t.Fatal("Maßnahme auf ein nicht geschütztes Ziel muss abgelehnt werden")
	}
	bad = []Active{{ID: "x", IncidentID: "inc; drop", Kind: KindSYNRate, Target: netip.MustParsePrefix("192.0.2.10/32"), Rate: 10}}
	if _, err := Render(testPolicy(), mgmt, now, DefaultTable, bad); err == nil {
		t.Fatal("Vorfalls-ID mit Metazeichen muss abgelehnt werden")
	}
}

func TestRenderSkipsExpiredBlocksAndKeepsOrderGuard(t *testing.T) {
	out, err := Render(testPolicy(), mgmt, now, DefaultTable, activeMitigations())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "2001:db8:bad::/48") {
		t.Error("abgelaufene Sperre darf nicht im Ruleset stehen")
	}
	// Trusted and management accept rules must come before any drop rule.
	acc := strings.Index(out, "@mgmt4 accept")
	drop := strings.Index(out, "@blk4 counter")
	if acc < 0 || drop < 0 || acc > drop {
		t.Errorf("Accept-Regeln müssen vor Drop-Regeln stehen (accept=%d drop=%d)", acc, drop)
	}
}

func TestRenderDeterministic(t *testing.T) {
	a, _ := Render(testPolicy(), mgmt, now, DefaultTable, activeMitigations())
	b, _ := Render(testPolicy(), mgmt, now, DefaultTable, activeMitigations())
	if a != b {
		t.Fatal("Render ist nicht deterministisch")
	}
}

func TestRenderRefusesManagementBlock(t *testing.T) {
	p := testPolicy()
	p.Blocks = []policy.ManualBlock{{RuleID: "x", Prefix: "192.0.2.200/32", ExpiresAt: now.Add(time.Hour)}}
	if _, err := Render(p, mgmt, now, DefaultTable, nil); err == nil {
		t.Fatal("Sperre des Management-Netzes muss abgelehnt werden")
	}
}

func TestRenderRejectsInjection(t *testing.T) {
	if _, err := Render(testPolicy(), mgmt, now, "x; flush ruleset", nil); err == nil {
		t.Fatal("Tabellenname mit Shell-/nft-Metazeichen muss abgelehnt werden")
	}
	p := testPolicy()
	p.Targets[0].Prefix = "192.0.2.10/32; flush ruleset"
	if _, err := Render(p, mgmt, now, DefaultTable, nil); err == nil {
		t.Fatal("manipuliertes Präfix muss abgelehnt werden")
	}
}

func TestParseCountersAndSetSize(t *testing.T) {
	data := []byte(`{"nftables":[{"metainfo":{"version":"1.0.9"}},
	{"counter":{"family":"inet","name":"t0_all","table":"sentinel_shield","packets":42,"bytes":4200}},
	{"counter":{"family":"inet","name":"t0_syn","table":"sentinel_shield","packets":7,"bytes":300}}]}`)
	c, err := ParseCounters(data)
	if err != nil {
		t.Fatal(err)
	}
	if c["t0_all"].Packets != 42 || c["t0_syn"].Bytes != 300 {
		t.Fatalf("falsche Zähler: %+v", c)
	}
	set := []byte(`{"nftables":[{"set":{"name":"dyn4","elem":["192.0.2.1",{"elem":{"val":"192.0.2.2"}}]}}]}`)
	n, err := ParseSetElements(set)
	if err != nil || n != 2 {
		t.Fatalf("ParseSetElements = %d, %v", n, err)
	}
}

// TestRenderValidatesWithKernelParser runs only where nft is installed.
func TestRenderValidatesWithKernelParser(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft nicht installiert")
	}
	out, err := Render(testPolicy(), mgmt, now, DefaultTable, activeMitigations())
	if err != nil {
		t.Fatal(err)
	}
	a := NewApplier(t.TempDir())
	if err := a.Check(out); err != nil {
		t.Fatalf("Kernel-Parser lehnt Ruleset ab: %v\n%s", err, out)
	}
}

// TestApplyIntegration loads the ruleset into the real kernel. It needs root and
// SS_NFT_INTEGRATION=1, because it changes the firewall of the host it runs on.
func TestApplyIntegration(t *testing.T) {
	if os.Getenv("SS_NFT_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("SS_NFT_INTEGRATION=1 und root erforderlich")
	}
	dir := t.TempDir()
	a := NewApplier(dir)
	a.Table = "sentinel_shield_test"
	t.Cleanup(func() { _ = a.Remove() })

	p := testPolicy()
	script, err := Render(p, mgmt, now, a.Table, activeMitigations())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(script); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	counters, err := a.Counters()
	if err != nil {
		t.Fatalf("Counters: %v", err)
	}
	if _, ok := counters["t0_all"]; !ok {
		t.Fatal("Zähler t0_all fehlt nach dem Anwenden")
	}

	// A broken policy-derived script must fail and leave the working table intact.
	broken := script + "\nthis is not nftables\n"
	if err := a.Apply(broken); err == nil {
		t.Fatal("kaputtes Ruleset wurde angewendet")
	}
	if !a.Installed() {
		t.Fatal("Tabelle muss nach fehlgeschlagenem Anwenden erhalten bleiben")
	}
}
