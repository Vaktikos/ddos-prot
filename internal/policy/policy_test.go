package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func basePolicy() *Policy {
	return &Policy{
		Version: 3,
		NodeID:  "node-1",
		Mode:    ModeDryRun,
		Targets: []Target{{
			Name: "web", Prefix: "192.0.2.10/32", Profile: "std",
			Services: []Service{{Name: "https", Protocol: ProtoTCP, Port: 443}},
		}},
		Profiles: map[string]Profile{"std": {
			Kind: "generic", TotalPPS: 100000, SYNPPS: 20000, UDPPPS: 50000,
			ConfirmSeconds: 5, ClearSeconds: 30,
			Mitigation: Mitigation{SYNRatePerSource: 100, AutoBlockSeconds: 300},
		}},
		Limits: Limits{MaxActiveBlocks: 100, MaxDynamicEntries: 1000},
	}
}

func TestValidateAcceptsBasePolicy(t *testing.T) {
	if err := Validate(basePolicy(), nil); err != nil {
		t.Fatalf("gültige Policy abgelehnt: %v", err)
	}
}

func TestValidateRejectsUnsafeInput(t *testing.T) {
	mgmt := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	cases := map[string]func(p *Policy){
		"unknown mode":      func(p *Policy) { p.Mode = "yolo" },
		"zero version":      func(p *Policy) { p.Version = 0 },
		"unknown profile":   func(p *Policy) { p.Targets[0].Profile = "nope" },
		"duplicate service": func(p *Policy) { p.Targets[0].Services = append(p.Targets[0].Services, p.Targets[0].Services[0]) },
		"bad port":          func(p *Policy) { p.Targets[0].Services[0].Port = 0 },
		"bad protocol":      func(p *Policy) { p.Targets[0].Services[0].Protocol = "icmp" },
		"catch-all target":  func(p *Policy) { p.Targets[0].Prefix = "0.0.0.0/0" },
		"no confirm window": func(p *Policy) { pr := p.Profiles["std"]; pr.ConfirmSeconds = 0; p.Profiles["std"] = pr },
		"no thresholds":     func(p *Policy) { p.Profiles["std"] = Profile{Kind: "generic", ConfirmSeconds: 1, ClearSeconds: 1} },
		"block on mgmt": func(p *Policy) {
			p.Blocks = []ManualBlock{{RuleID: "r", Prefix: "203.0.113.7/32", ExpiresAt: time.Now().Add(time.Hour)}}
		},
		"block without ttl": func(p *Policy) { p.Blocks = []ManualBlock{{RuleID: "r", Prefix: "198.51.100.7/32"}} },
		"block over limit": func(p *Policy) {
			p.Limits.MaxActiveBlocks = 1
			p.Blocks = []ManualBlock{{RuleID: "a", Prefix: "198.51.100.1/32", ExpiresAt: time.Now().Add(time.Hour)}, {RuleID: "b", Prefix: "198.51.100.2/32", ExpiresAt: time.Now().Add(time.Hour)}}
		},
		"block trusted source": func(p *Policy) {
			p.Trusted = []string{"198.51.100.0/24"}
			p.Blocks = []ManualBlock{{RuleID: "r", Prefix: "198.51.100.9/32", ExpiresAt: time.Now().Add(time.Hour)}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := basePolicy()
			mutate(p)
			if err := Validate(p, mgmt); err == nil {
				t.Fatalf("erwartete Ablehnung")
			}
		})
	}
}

func TestSignAndOpenRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, err := Sign(priv, basePolicy())
	if err != nil {
		t.Fatal(err)
	}
	p, err := Open(pub, env, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if p.Version != 3 || p.Targets[0].Prefix != "192.0.2.10/32" {
		t.Fatalf("unerwarteter Inhalt: %+v", p)
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	env, _ := Sign(priv, basePolicy())

	tampered := env
	tampered.Body = strings.Replace(env.Body, `"mode":"dry_run"`, `"mode":"auto"`, 1)
	if _, err := Open(pub, tampered, nil); err == nil {
		t.Fatal("manipulierter Body wurde akzeptiert")
	}

	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Open(otherPub, env, nil); err == nil {
		t.Fatal("Signatur mit fremdem Schlüssel wurde akzeptiert")
	}

	wrongVersion := env
	wrongVersion.Version = 99
	if _, err := Open(pub, wrongVersion, nil); err == nil {
		t.Fatal("falsche Version im Envelope wurde akzeptiert")
	}
}

func TestValidateRejectsCatchAllTrustedSource(t *testing.T) {
	for _, s := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/4"} {
		p := basePolicy()
		p.Trusted = []string{s}
		if err := Validate(p, nil); err == nil {
			t.Errorf("trusted %s muss abgelehnt werden", s)
		}
	}
}
