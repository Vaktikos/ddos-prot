package mitigate

import (
	"testing"
	"time"

	"github.com/vaktikos/ddos-prot/internal/detect"
	"github.com/vaktikos/ddos-prot/internal/policy"
)

var now = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func profile() policy.Profile {
	return policy.Profile{Kind: "generic", SYNPPS: 20000, ConfirmSeconds: 5, ClearSeconds: 30,
		Mitigation: policy.Mitigation{SYNRatePerSource: 100, UDPRatePerSource: 500, AutoBlockSeconds: 300}}
}

func event(cat detect.Category, v detect.Verdict) detect.Event {
	return detect.Event{ID: "inc42", Target: "192.0.2.10/32", Category: cat, Verdict: v,
		Started: now, PeakPPS: 90000, PeakSYNPPS: 80000}
}

func TestOnlyConfirmedAttacksTriggerMitigation(t *testing.T) {
	for _, v := range []detect.Verdict{detect.VerdictSpike, detect.VerdictSuspicious} {
		d := Decide(event(detect.CategorySYNFlood, v), profile(), policy.ModeAuto, 0, 100)
		if len(d.Plans) != 0 || d.Escalate {
			t.Fatalf("Verdict %s darf keine Maßnahme auslösen: %+v", v, d)
		}
	}
}

func TestModesGateApplication(t *testing.T) {
	ev := event(detect.CategorySYNFlood, detect.VerdictConfirmed)

	dry := Decide(ev, profile(), policy.ModeDryRun, 0, 100)
	if len(dry.Plans) != 1 || dry.Plans[0].Status != StatusProposed || !dry.Plans[0].DryRun {
		t.Fatalf("dry_run muss Vorschlag ohne Anwendung erzeugen: %+v", dry.Plans)
	}
	if len(Applied(dry.Plans)) != 0 {
		t.Fatal("dry_run darf nichts als aktiv markieren")
	}

	appr := Decide(ev, profile(), policy.ModeApproval, 0, 100)
	if appr.Plans[0].Status != StatusPendingApproval || len(Applied(appr.Plans)) != 0 {
		t.Fatalf("approval muss auf Freigabe warten: %+v", appr.Plans)
	}

	auto := Decide(ev, profile(), policy.ModeAuto, 0, 100)
	if auto.Plans[0].Status != StatusApplied || len(Applied(auto.Plans)) != 1 {
		t.Fatalf("auto muss bestätigte Angriffe mitigieren: %+v", auto.Plans)
	}
	if !auto.Escalate {
		t.Fatal("bestätigte Angriffe müssen Administratoren benachrichtigen")
	}
}

func TestBlocksWithheldWhenDynamicSetFull(t *testing.T) {
	d := Decide(event(detect.CategorySYNFlood, detect.VerdictConfirmed), profile(), policy.ModeAuto, 100, 100)
	if d.Plans[0].AutoBlockSeconds != 0 {
		t.Fatalf("volle Sperrliste darf keine neuen Quellsperren erzeugen: %+v", d.Plans[0])
	}
	if d.Plans[0].Rate != 100 {
		t.Fatal("Ratenbegrenzung muss trotz voller Sperrliste greifen")
	}
}

func TestUnsupportedCategoryOnlyEscalates(t *testing.T) {
	d := Decide(event(detect.CategoryICMPFlood, detect.VerdictConfirmed), profile(), policy.ModeAuto, 0, 100)
	if len(d.Plans) != 0 || !d.Escalate {
		t.Fatalf("ICMP-Flut ohne Profilregel muss nur eskalieren: %+v", d)
	}
}

func TestUDPRuleRequiresProfileSetting(t *testing.T) {
	p := profile()
	p.Mitigation.UDPRatePerSource = 0
	d := Decide(event(detect.CategoryUDPFlood, detect.VerdictConfirmed), p, policy.ModeAuto, 0, 100)
	if len(d.Plans) != 0 {
		t.Fatalf("ohne UDP-Rate im Profil keine UDP-Maßnahme: %+v", d.Plans)
	}
}

func TestPendingApprovalExpires(t *testing.T) {
	d := Decide(event(detect.CategorySYNFlood, detect.VerdictConfirmed), profile(), policy.ModeApproval, 0, 100)
	kept, expired := ExpirePending(d.Plans, now.Add(10*time.Minute), 5*time.Minute)
	if len(kept) != 0 || len(expired) != 1 {
		t.Fatalf("unbeantwortete Freigabe muss ablaufen: kept=%d expired=%d", len(kept), len(expired))
	}
	kept, _ = ExpirePending(d.Plans, now.Add(time.Minute), 5*time.Minute)
	if len(kept) != 1 {
		t.Fatal("frische Freigabe darf nicht ablaufen")
	}
}

func TestWithoutIncidentRemovesOnlyThatIncident(t *testing.T) {
	plans := []Plan{{ID: "a", IncidentID: "inc1"}, {ID: "b", IncidentID: "inc2"}, {ID: "c", IncidentID: "inc1"}}
	kept := WithoutIncident(plans, "inc1")
	if len(kept) != 1 || kept[0].ID != "b" {
		t.Fatalf("falsche Entfernung: %+v", kept)
	}
}

func TestFragmentAndInvalidFlagMitigationFollowProfile(t *testing.T) {
	p := profile()
	p.Mitigation.DropFragments = true
	d := Decide(event(detect.CategoryFragFlood, detect.VerdictConfirmed), p, policy.ModeAuto, 0, 100)
	if len(d.Plans) != 1 || d.Plans[0].Kind != "drop_fragments" || d.Plans[0].AutoBlockSeconds != 0 {
		t.Fatalf("Fragmentflut mit erlaubtem Drop: %+v", d.Plans)
	}
	// Not allowed by the profile: only escalate.
	d = Decide(event(detect.CategoryInvalidFlags, detect.VerdictConfirmed), profile(), policy.ModeAuto, 0, 100)
	if len(d.Plans) != 0 || !d.Escalate {
		t.Fatalf("ohne Profilfreigabe darf nur eskaliert werden: %+v", d)
	}
	p.Mitigation.DropInvalid = true
	d = Decide(event(detect.CategoryInvalidFlags, detect.VerdictConfirmed), p, policy.ModeDryRun, 0, 100)
	if len(d.Plans) != 1 || !d.Plans[0].DryRun {
		t.Fatalf("Dry-Run muss auch hier nur vorschlagen: %+v", d.Plans)
	}
}

func TestHTTPFloodPlansL7BlockOnlyWhenProfileAsks(t *testing.T) {
	prof := profile()
	prof.HTTPRejectRPS = 100
	ev := event(detect.CategoryHTTPFlood, detect.VerdictConfirmed)
	d := Decide(ev, prof, policy.ModeAuto, 0, 100)
	if len(d.Plans) != 0 {
		t.Fatalf("ohne l7_source_rps keine automatische Maßnahme: %+v", d.Plans)
	}
	prof.Mitigation.L7SourceRPS, prof.Mitigation.L7BlockSeconds = 30, 120
	d = Decide(ev, prof, policy.ModeAuto, 0, 100)
	if len(d.Plans) != 1 || d.Plans[0].Kind != KindL7Block || d.Plans[0].Rate != 30 || d.Plans[0].AutoBlockSeconds != 120 {
		t.Fatalf("plan: %+v", d.Plans)
	}
	d = Decide(ev, prof, policy.ModeApproval, 0, 100)
	if d.Plans[0].Status != StatusPendingApproval {
		t.Fatalf("im Freigabemodus muss der Plan warten: %+v", d.Plans[0])
	}
}
