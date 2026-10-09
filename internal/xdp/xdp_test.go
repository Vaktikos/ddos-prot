package xdp

import (
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

// These tests load a real XDP program onto the loopback interface. They need root and
// SS_XDP_INTEGRATION=1 because they change kernel state of the host they run on.
func requireXDP(t *testing.T) *Manager {
	t.Helper()
	if os.Getenv("SS_XDP_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("SS_XDP_INTEGRATION=1 und root erforderlich")
	}
	m, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Attach([]string{"lo"}, ModeGeneric, ""); err != nil {
		m.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Detach("", []string{"lo"}); _ = m.Close() })
	return m
}

// sendAndCount sends n datagrams to a local receiver and returns how many arrived.
func sendAndCount(t *testing.T, n int) int {
	t.Helper()
	rx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer rx.Close()
	tx, err := net.DialUDP("udp4", nil, rx.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	for i := 0; i < n; i++ {
		if _, err := tx.Write([]byte("probe")); err != nil {
			t.Fatal(err)
		}
	}
	got := 0
	buf := make([]byte, 64)
	for {
		_ = rx.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, _, err := rx.ReadFromUDP(buf); err != nil {
			return got
		}
		got++
	}
}

var loopback = netip.MustParsePrefix("127.0.0.1/32")

func TestXDPBlocksAndPasses(t *testing.T) {
	m := requireXDP(t)
	if got := sendAndCount(t, 20); got != 20 {
		t.Fatalf("ohne Sperre müssen alle Pakete ankommen: %d/20", got)
	}
	if err := m.Block(loopback, time.Now().Add(time.Hour), OwnerManual); err != nil {
		t.Fatal(err)
	}
	if got := sendAndCount(t, 20); got != 0 {
		t.Fatalf("gesperrte Quelle: %d Pakete kamen durch", got)
	}
	st, err := m.Stats()
	if err != nil || st.DroppedPackets < 20 {
		t.Fatalf("Verwurf nicht gezählt: %+v %v", st, err)
	}

	// The allow list wins over a block, so management access cannot be filtered.
	if err := m.SetAllow([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}); err != nil {
		t.Fatal(err)
	}
	if got := sendAndCount(t, 10); got != 10 {
		t.Fatalf("Allowlist muss Sperre übersteuern: %d/10", got)
	}
	if err := m.SetAllow(nil); err != nil {
		t.Fatal(err)
	}
	if got := sendAndCount(t, 10); got != 0 {
		t.Fatalf("nach Entfernen der Allowlist wieder gesperrt erwartet: %d", got)
	}

	if err := m.Unblock(loopback); err != nil {
		t.Fatal(err)
	}
	if got := sendAndCount(t, 10); got != 10 {
		t.Fatalf("nach Aufheben müssen Pakete ankommen: %d/10", got)
	}
}

func TestXDPBlockExpiresInKernelWithoutUserspace(t *testing.T) {
	m := requireXDP(t)
	if err := m.Block(loopback, time.Now().Add(1500*time.Millisecond), OwnerAuto); err != nil {
		t.Fatal(err)
	}
	if got := sendAndCount(t, 5); got != 0 {
		t.Fatalf("Block muss zunächst greifen: %d", got)
	}
	time.Sleep(1700 * time.Millisecond) // no Expire() call: the kernel entry itself has run out
	if got := sendAndCount(t, 5); got != 5 {
		t.Fatalf("abgelaufener Block darf nicht mehr filtern: %d/5", got)
	}
}

func TestXDPCountsSourcesTowardProtectedTargets(t *testing.T) {
	m := requireXDP(t)
	if err := m.SetProtected([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	m.Sample(now, 0, 10) // baseline
	sendAndCount(t, 200)
	rates := m.Sample(now.Add(time.Second), 50, 10)
	if len(rates) == 0 || rates[0].Addr != loopback.Addr() || rates[0].PPS < 100 {
		t.Fatalf("Quelle 127.0.0.1 mit >= 100 pps erwartet: %+v", rates)
	}
	// Traffic to a destination that is not protected must not be counted.
	if err := m.SetProtected(nil); err != nil {
		t.Fatal(err)
	}
	m.Sample(now.Add(2*time.Second), 0, 10)
	sendAndCount(t, 100)
	if rates := m.Sample(now.Add(3*time.Second), 10, 10); len(rates) != 0 {
		t.Fatalf("ungeschütztes Ziel darf nicht gezählt werden: %+v", rates)
	}
}

func TestPrefixKeys(t *testing.T) {
	k := key4(netip.MustParsePrefix("192.0.2.0/24"))
	if k.Prefixlen != 24 {
		t.Fatalf("Präfixlänge = %d", k.Prefixlen)
	}
	k6 := key6(netip.MustParsePrefix("2001:db8::/32"))
	if k6.Prefixlen != 32 || k6.Addr[0] != 0x20 || k6.Addr[1] != 0x01 {
		t.Fatalf("v6-Schlüssel falsch: %+v", k6)
	}
}

// A pinned link keeps filtering after the agent process is gone, and a restarted agent
// replaces the program in place.
func TestXDPSurvivesAgentExitAndIsReplacedOnRestart(t *testing.T) {
	if os.Getenv("SS_XDP_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("SS_XDP_INTEGRATION=1 und root erforderlich")
	}
	dir := "/sys/fs/bpf/ss-test"
	if !EnsureBPFFS("/sys/fs/bpf") {
		t.Skip("bpffs nicht einhängbar")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := first.Attach([]string{"lo"}, ModeGeneric, dir)
	if err != nil || !pinned {
		t.Fatalf("Pin erwartet: %v %v", pinned, err)
	}
	if err := first.Block(loopback, time.Now().Add(time.Hour), OwnerManual); err != nil {
		t.Fatal(err)
	}
	_ = first.Close() // the agent process "exits" without detaching

	if got := sendAndCount(t, 10); got != 0 {
		t.Fatalf("Filter muss nach Prozessende weiterlaufen: %d Pakete kamen durch", got)
	}

	second, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Attach([]string{"lo"}, ModeGeneric, dir); err != nil {
		t.Fatalf("Neustart: %v", err)
	}
	if got := sendAndCount(t, 10); got != 10 {
		t.Fatalf("das neue Programm mit leeren Maps muss ersetzen: %d/10", got)
	}
	if err := second.Detach(dir, []string{"lo"}); err != nil {
		t.Fatal(err)
	}
	_ = second.Close()
	_ = os.Remove(dir)
}
