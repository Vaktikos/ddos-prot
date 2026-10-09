package l7

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseLine(t *testing.T) {
	ok := `203.0.113.7 [2026-10-09T12:00:00+00:00] "GET /login?a=b HTTP/1.1" 429 limit=REJECTED ua="curl/8 \x22x"`
	e, good := ParseLine(ok)
	if !good || e.Addr != netip.MustParseAddr("203.0.113.7") || e.Status != 429 {
		t.Fatalf("%+v %v", e, good)
	}
	if e, good := ParseLine(`::ffff:198.51.100.1 [t] "GET / HTTP/1.1" 503 limit=- ua="-"`); !good || e.Addr != netip.MustParseAddr("198.51.100.1") {
		t.Fatalf("v4-mapped: %+v %v", e, good)
	}
	for _, bad := range []string{"", "garbage", `not-an-ip [t] "GET / HTTP/1.1" 429 x`, `1.2.3.4 t "GET /" 429`,
		`1.2.3.4 [t] "GET / HTTP/1.1" 99999 x`, `1.2.3.4 [t] "GET / HTTP/1.1" abc x`, `1.2.3.4 [t] "unterminated 429`} {
		if _, good := ParseLine(bad); good {
			t.Fatalf("muss abgelehnt werden: %q", bad)
		}
	}
}

func FuzzParseLine(f *testing.F) {
	f.Add(`1.2.3.4 [t] "GET / HTTP/1.1" 429 limit=- ua="-"`)
	f.Fuzz(func(t *testing.T, s string) { ParseLine(s) })
}

func TestTailerStartsAtEndFollowsAppendsAndRotation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ss_reject.log")
	if err := os.WriteFile(p, []byte("old line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tl := NewTailer(p)
	defer tl.Close()
	if lines, err := tl.Poll(); err != nil || len(lines) != 0 {
		t.Fatalf("alte Zeilen dürfen nicht erneut gelesen werden: %v %v", lines, err)
	}
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("a\nb\npart")
	lines, _ := tl.Poll()
	if strings.Join(lines, ",") != "a,b" {
		t.Fatalf("vollständige Zeilen: %v", lines)
	}
	f.WriteString("ial\n")
	f.Close()
	lines, _ = tl.Poll()
	if strings.Join(lines, ",") != "partial" {
		t.Fatalf("Rest einer Zeile: %v", lines)
	}
	// rotation: rename and create anew
	os.Rename(p, p+".1")
	os.WriteFile(p, []byte("n1\nn2\n"), 0o600)
	lines, _ = tl.Poll()
	if strings.Join(lines, ",") != "n1,n2" {
		t.Fatalf("nach Rotation: %v", lines)
	}
	// truncation in place
	os.WriteFile(p, []byte("t1\n"), 0o600)
	lines, _ = tl.Poll()
	if strings.Join(lines, ",") != "t1" {
		t.Fatalf("nach Kürzen: %v", lines)
	}
}

func TestTailerSkipsAheadWhenLogGrowsTooFast(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.log")
	os.WriteFile(p, nil, 0o600)
	tl := NewTailer(p)
	defer tl.Close()
	tl.Poll()
	line := strings.Repeat("x", 99) + "\n"
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(strings.Repeat(line, (MaxReadPerPoll/100)*2))
	f.Close()
	lines, err := tl.Poll()
	if err != nil || len(lines) == 0 || tl.Skipped == 0 {
		t.Fatalf("lines=%d skipped=%d err=%v", len(lines), tl.Skipped, err)
	}
}

func TestTailerMissingFileIsAnErrorThenRecovers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "later.log")
	tl := NewTailer(p)
	defer tl.Close()
	if _, err := tl.Poll(); err == nil {
		t.Fatal("fehlende Datei muss gemeldet werden")
	}
	os.WriteFile(p, []byte("first\n"), 0o600)
	lines, err := tl.Poll()
	if err != nil || len(lines) != 1 {
		t.Fatalf("Datei erscheint später: %v %v", lines, err)
	}
}

func TestWindowRates(t *testing.T) {
	w := NewWindow(10)
	now := time.Unix(1_000_000, 0)
	a, b := netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2")
	for i := 0; i < 10; i++ {
		w.Add(now.Add(time.Duration(i-9)*time.Second), a, 50)
		w.Add(now.Add(time.Duration(i-9)*time.Second), b, 5)
	}
	total, per := w.Rates(now)
	if total != 55 || per[a] != 50 || per[b] != 5 {
		t.Fatalf("total=%v per=%v", total, per)
	}
	total, _ = w.Rates(now.Add(20 * time.Second))
	if total != 0 {
		t.Fatalf("alte Werte müssen verfallen: %v", total)
	}
}

func TestWindowBoundsDistinctSources(t *testing.T) {
	w := NewWindow(5)
	now := time.Unix(2_000_000, 0)
	for i := 0; i < MaxSources+500; i++ {
		w.Add(now, netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 1)
	}
	total, per := w.Rates(now)
	if len(per) != MaxSources || w.Overflow != 500 || total*5 != float64(MaxSources+500) {
		t.Fatalf("per=%d overflow=%d total=%v", len(per), w.Overflow, total)
	}
}
