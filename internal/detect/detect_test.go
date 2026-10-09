package detect

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func thresholds() Thresholds {
	return Thresholds{
		TotalPPS: 100000, SYNPPS: 20000, UDPPPS: 50000, ICMPPPS: 5000,
		BaselineMultiplier: 3, MinPPS: 2000, ConfirmSeconds: 5, ClearSeconds: 4,
	}
}

// feed sends one-second samples with the given per-second packet counts.
type feeder struct {
	t  *testing.T
	e  *Engine
	th Thresholds
	at time.Time
	ch []Change
}

func (f *feeder) second(target string, pkts, syn, udp, icmp uint64) {
	f.t.Helper()
	f.at = f.at.Add(time.Second)
	changes, err := f.e.Observe(target, Sample{
		At: f.at, Interval: time.Second, Packets: pkts, Bytes: pkts * 500,
		SYN: syn, UDP: udp, ICMP: icmp,
	}, f.th)
	if err != nil {
		f.t.Fatalf("Observe: %v", err)
	}
	f.ch = append(f.ch, changes...)
}

func newFeeder(t *testing.T, th Thresholds) *feeder {
	return &feeder{t: t, e: NewEngine(func() string { return "evt" }), th: th, at: t0}
}

func kinds(ch []Change) []string {
	var out []string
	for _, c := range ch {
		out = append(out, c.Kind+":"+string(c.Event.Verdict))
	}
	return out
}

func TestQuietTrafficProducesNoEvents(t *testing.T) {
	f := newFeeder(t, thresholds())
	for i := 0; i < 300; i++ {
		f.second("192.0.2.10/32", 1000+uint64(i%7)*20, 50, 400, 5)
	}
	if len(f.ch) != 0 {
		t.Fatalf("normaler Verkehr erzeugte Ereignisse: %v", kinds(f.ch))
	}
}

func TestSYNFloodIsConfirmedAfterSustainAndClosesAfterClear(t *testing.T) {
	f := newFeeder(t, thresholds())
	for i := 0; i < 60; i++ {
		f.second("192.0.2.10/32", 1000, 50, 400, 5)
	}
	for i := 0; i < 10; i++ {
		f.second("192.0.2.10/32", 60000, 50000, 0, 0)
	}
	for i := 0; i < 10; i++ {
		f.second("192.0.2.10/32", 1000, 50, 400, 5)
	}
	got := kinds(f.ch)
	want := []string{"opened:suspicious_anomaly", "escalated:confirmed_attack", "closed:confirmed_attack"}
	if len(got) != len(want) {
		t.Fatalf("Ereignisse = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Ereignisse = %v, want %v", got, want)
		}
	}
	closed := f.ch[2].Event
	if closed.Category != CategorySYNFlood {
		t.Errorf("Kategorie = %s, want syn_flood", closed.Category)
	}
	if closed.PeakSYNPPS < 50000 {
		t.Errorf("PeakSYNPPS = %.0f, want >= 50000", closed.PeakSYNPPS)
	}
	if closed.Confidence < 0.85 {
		t.Errorf("Konfidenz = %.2f, want >= 0.85", closed.Confidence)
	}
	if !closed.Ended.After(closed.Started) {
		t.Errorf("Ende %v liegt nicht nach Start %v", closed.Ended, closed.Started)
	}
}

func TestShortBurstIsNotConfirmed(t *testing.T) {
	f := newFeeder(t, thresholds())
	for i := 0; i < 60; i++ {
		f.second("198.51.100.1/32", 1000, 50, 400, 5)
	}
	f.second("198.51.100.1/32", 500000, 0, 500000, 0) // one-second UDP burst
	for i := 0; i < 10; i++ {
		f.second("198.51.100.1/32", 1000, 50, 400, 5)
	}
	for _, c := range f.ch {
		if c.Event.Verdict == VerdictConfirmed {
			t.Fatalf("einzelne Sekunde darf keinen bestätigten Angriff auslösen: %v", kinds(f.ch))
		}
	}
	if len(f.ch) != 2 || f.ch[0].Kind != "opened" || f.ch[1].Kind != "closed" {
		t.Fatalf("erwartet opened+closed, erhalten %v", kinds(f.ch))
	}
}

func TestAdaptiveSustainedAnomalyIsSuspiciousNotConfirmed(t *testing.T) {
	th := thresholds()
	th.TotalPPS = 0 // no absolute packet threshold; only the baseline can react
	f := newFeeder(t, th)
	for i := 0; i < 60; i++ {
		f.second("192.0.2.20/32", 1000, 50, 400, 5)
	}
	for i := 0; i < 10; i++ {
		f.second("192.0.2.20/32", 9000, 100, 8000, 0)
	}
	var verdicts []Verdict
	for _, c := range f.ch {
		verdicts = append(verdicts, c.Event.Verdict)
	}
	for _, v := range verdicts {
		if v == VerdictConfirmed {
			t.Fatalf("adaptive Anomalie ohne absolute Schwelle darf nicht bestätigt werden: %v", kinds(f.ch))
		}
	}
	// Starts as a plain spike and is escalated only after the window is sustained.
	got := kinds(f.ch)
	if len(got) != 2 || got[0] != "opened:traffic_spike" || got[1] != "escalated:suspicious_anomaly" {
		t.Fatalf("erwartet spike -> verdächtige Anomalie, erhalten %v", got)
	}
}

func TestBenignSpikeIsTrafficSpike(t *testing.T) {
	th := thresholds()
	f := newFeeder(t, th)
	for i := 0; i < 60; i++ {
		f.second("192.0.2.30/32", 1000, 20, 300, 2)
	}
	f.second("192.0.2.30/32", 4000, 40, 3000, 2) // above 3x baseline, below all absolute thresholds
	for i := 0; i < 10; i++ {
		f.second("192.0.2.30/32", 1000, 20, 300, 2)
	}
	if len(f.ch) != 2 || f.ch[0].Event.Verdict != VerdictSpike {
		t.Fatalf("erwartet traffic_spike, erhalten %v", kinds(f.ch))
	}
}

func TestAdaptiveRuleWaitsForWarmup(t *testing.T) {
	th := thresholds()
	th.TotalPPS = 0
	f := newFeeder(t, th)
	for i := 0; i < 10; i++ {
		f.second("192.0.2.40/32", 1000, 0, 0, 0)
	}
	f.second("192.0.2.40/32", 50000, 0, 0, 0)
	if len(f.ch) != 0 {
		t.Fatalf("adaptive Regel vor Warmup aktiv: %v", kinds(f.ch))
	}
}

func TestIPv6ICMPFloodIsConfirmed(t *testing.T) {
	f := newFeeder(t, thresholds())
	for i := 0; i < 40; i++ {
		f.second("2001:db8::/48", 800, 0, 100, 10)
	}
	for i := 0; i < 8; i++ {
		f.second("2001:db8::/48", 9000, 0, 0, 8000)
	}
	var confirmed *Event
	for _, c := range f.ch {
		if c.Event.Verdict == VerdictConfirmed {
			ev := c.Event
			confirmed = &ev
		}
	}
	if confirmed == nil || confirmed.Category != CategoryICMPFlood {
		t.Fatalf("erwartet bestätigter icmp_flood für IPv6, erhalten %v", kinds(f.ch))
	}
}

func TestTargetsAreIndependent(t *testing.T) {
	f := newFeeder(t, thresholds())
	for i := 0; i < 10; i++ {
		f.second("192.0.2.50/32", 60000, 50000, 0, 0)
	}
	f.second("192.0.2.51/32", 1000, 0, 0, 0)
	if _, ok := f.e.Active("192.0.2.51/32"); ok {
		t.Fatal("Angriff auf ein Ziel darf kein anderes Ziel markieren")
	}
	if _, ok := f.e.Active("192.0.2.50/32"); !ok {
		t.Fatal("angegriffenes Ziel muss aktiv sein")
	}
}

func TestEngineRejectsInvalidInput(t *testing.T) {
	e := NewEngine(nil)
	if _, err := e.Observe("x", Sample{At: t0}, thresholds()); err == nil {
		t.Error("Intervall 0 muss abgelehnt werden")
	}
	if _, err := e.Observe("x", Sample{At: t0, Interval: time.Second}, Thresholds{}); err == nil {
		t.Error("fehlende Dauerwerte müssen abgelehnt werden")
	}
}

func TestForgetClosesOpenEvent(t *testing.T) {
	f := newFeeder(t, thresholds())
	for i := 0; i < 10; i++ {
		f.second("192.0.2.60/32", 60000, 50000, 0, 0)
	}
	ch, ok := f.e.Forget("192.0.2.60/32", f.at)
	if !ok || ch.Kind != "closed" {
		t.Fatalf("Forget soll offenes Ereignis schließen, erhalten %+v", ch)
	}
	if _, active := f.e.Active("192.0.2.60/32"); active {
		t.Fatal("nach Forget darf kein Ereignis aktiv sein")
	}
}

func TestHighEventRateStaysBounded(t *testing.T) {
	f := newFeeder(t, thresholds())
	// 200 targets flipping between attack and quiet every 10 seconds.
	for round := 0; round < 6; round++ {
		for n := 0; n < 200; n++ {
			target := "10.0.0." + string(rune('a'+n%26)) + "/32"
			for i := 0; i < 10; i++ {
				if round%2 == 0 {
					f.e.Observe(target, Sample{At: f.at.Add(time.Duration(i) * time.Second), Interval: time.Second, Packets: 90000, SYN: 80000}, thresholds())
				} else {
					f.e.Observe(target, Sample{At: f.at.Add(time.Duration(i) * time.Second), Interval: time.Second, Packets: 500}, thresholds())
				}
			}
		}
		f.at = f.at.Add(10 * time.Second)
	}
	if len(f.e.targets) > 200 {
		t.Fatalf("unerwartete Zustandsanzahl %d", len(f.e.targets))
	}
}

func TestConnectionRateDetectsSYNSurgeWithoutRatioCheck(t *testing.T) {
	// Established game traffic: many packets, almost no new connections. Must stay quiet.
	th := Thresholds{ConnPPS: 40, ConfirmSeconds: 3, ClearSeconds: 4}
	e := NewEngine(func() string { return "svc" })
	at := t0
	for i := 0; i < 20; i++ {
		at = at.Add(time.Second)
		if ch, _ := e.Observe("192.0.2.10/32|tcp/25565", Sample{At: at, Interval: time.Second, Packets: 5000, SYN: 3}, th); len(ch) != 0 {
			t.Fatalf("Spielverkehr mit wenigen neuen Verbindungen darf keinen Vorfall auslösen: %v", ch)
		}
	}
	// Connection flood on the same port: 200 SYN/s with few other packets.
	var confirmed bool
	for i := 0; i < 6; i++ {
		at = at.Add(time.Second)
		ch, _ := e.Observe("192.0.2.10/32|tcp/25565", Sample{At: at, Interval: time.Second, Packets: 300, SYN: 200}, th)
		for _, c := range ch {
			if c.Event.Verdict == VerdictConfirmed && c.Event.Category == CategoryConnRate {
				confirmed = true
			}
		}
	}
	if !confirmed {
		t.Fatal("Verbindungsflut auf einem Dienst muss als bestätigte connection_rate erkannt werden")
	}
}
