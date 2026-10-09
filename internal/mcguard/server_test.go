package mcguard

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeBackend records what the game server would see and echoes everything back.
type fakeBackend struct {
	ln       net.Listener
	accepted atomic.Int64
	mu       sync.Mutex
	first    [][]byte
}

func newBackend(t *testing.T, expectProxyHeader bool) *fakeBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBackend{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b.accepted.Add(1)
			go func() {
				defer c.Close()
				// TCP may split what the guard writes; collect until the stream pauses.
				var got []byte
				buf := make([]byte, 4096)
				for {
					_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
					n, err := c.Read(buf)
					got = append(got, buf[:n]...)
					if err != nil {
						break
					}
				}
				_ = c.SetReadDeadline(time.Time{})
				b.mu.Lock()
				b.first = append(b.first, got)
				b.mu.Unlock()
				_, _ = c.Write(got)
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return b
}

func (b *fakeBackend) firstBytes(i int) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if i >= len(b.first) {
		return nil
	}
	return b.first[i]
}

func startGuard(t *testing.T, mutate func(*Config), backend *fakeBackend) (*Server, string) {
	t.Helper()
	cfg := Config{Listen: "127.0.0.1:25565", Backend: backend.ln.Addr().String(), HandshakeTimeoutMS: 300, IdleAfterHandshake: 400}
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return srv, ln.Addr().String()
}

// login sends a handshake plus a login-start-like packet and returns what came back.
func login(t *testing.T, addr string, host string) ([]byte, error) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	pkt := append(handshake(765, host, 25565, StateLogin), 0x04, 0x00, 0x02, 'a', 'b')
	if _, err := c.Write(pkt); err != nil {
		return nil, err
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	return buf[:n], err
}

func TestValidClientIsForwardedUnchanged(t *testing.T) {
	be := newBackend(t, false)
	srv, addr := startGuard(t, nil, be)
	reply, err := login(t, addr, "mc.example.net")
	if err != nil {
		t.Fatalf("gültiger Client: %v", err)
	}
	want := append(handshake(765, "mc.example.net", 25565, StateLogin), 0x04, 0x00, 0x02, 'a', 'b')
	if !bytes.Equal(be.firstBytes(0), want) || !bytes.Equal(reply, want) {
		t.Fatalf("der Server muss exakt die Client-Bytes sehen und antworten können:\nserver: %x\nreply:  %x", be.firstBytes(0), reply)
	}
	if st := srv.Stats(); st.HandshakeOK != 1 || st.Logins != 1 || st.Invalid != 0 {
		t.Fatalf("Statistik: %+v", st)
	}
}

func TestGarbageNeverReachesTheServer(t *testing.T) {
	be := newBackend(t, false)
	srv, addr := startGuard(t, nil, be)
	for _, payload := range [][]byte{[]byte("GET / HTTP/1.1\r\n\r\n"), bytes.Repeat([]byte{0xff}, 64), {0x00}} {
		c, _ := net.Dial("tcp", addr)
		_, _ = c.Write(payload)
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, err := c.Read(make([]byte, 16))
		c.Close()
		if err == nil {
			t.Fatal("die Verbindung muss geschlossen werden")
		}
	}
	time.Sleep(50 * time.Millisecond)
	if be.accepted.Load() != 0 {
		t.Fatalf("der Server hat %d Verbindungen gesehen, erwartet 0", be.accepted.Load())
	}
	if srv.Stats().Invalid != 3 {
		t.Fatalf("Invalid = %d, erwartet 3", srv.Stats().Invalid)
	}
}

func TestRepeatedInvalidHandshakesBanTheSource(t *testing.T) {
	be := newBackend(t, false)
	srv, addr := startGuard(t, func(c *Config) { c.BanAfterInvalid = 3 }, be)
	for i := 0; i < 3; i++ {
		c, _ := net.Dial("tcp", addr)
		_, _ = c.Write([]byte("junk junk junk"))
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = c.Read(make([]byte, 8))
		c.Close()
	}
	time.Sleep(50 * time.Millisecond)
	if srv.Stats().BansIssued != 1 || len(srv.Stats().Bans) != 1 {
		t.Fatalf("nach 3 ungültigen Handshakes muss gesperrt sein: %+v", srv.Stats())
	}
	// Even a perfectly valid client from the banned address is dropped without being read.
	if _, err := login(t, addr, "mc.example.net"); err == nil {
		t.Fatal("eine gesperrte Quelle darf nicht durchkommen")
	}
	if srv.Stats().BannedDrops == 0 || be.accepted.Load() != 0 {
		t.Fatalf("Verwurf nicht gezählt oder Server erreicht: %+v", srv.Stats())
	}
}

func TestAllowListedSourcesAreNeverBannedOrLimited(t *testing.T) {
	be := newBackend(t, false)
	srv, addr := startGuard(t, func(c *Config) {
		c.BanAfterInvalid = 2
		c.AllowCIDRs = []string{"127.0.0.0/8"}
		c.NewConnPerSecond, c.NewConnBurst = 1, 1
	}, be)
	for i := 0; i < 6; i++ {
		c, _ := net.Dial("tcp", addr)
		_, _ = c.Write([]byte("junk"))
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = c.Read(make([]byte, 4))
		c.Close()
	}
	for i := 0; i < 5; i++ {
		if _, err := login(t, addr, "mc.example.net"); err != nil {
			t.Fatalf("vertrauenswürdige Quelle wurde begrenzt (Versuch %d): %v", i, err)
		}
	}
	if srv.Stats().BansIssued != 0 || srv.Stats().RateLimited != 0 {
		t.Fatalf("keine Sperre und kein Limit erwartet: %+v", srv.Stats())
	}
}

func TestPerSourceConnectionLimit(t *testing.T) {
	be := newBackend(t, false)
	srv, addr := startGuard(t, func(c *Config) { c.MaxPerSource = 2 }, be)
	var held []net.Conn
	for i := 0; i < 2; i++ {
		c, _ := net.Dial("tcp", addr)
		_, _ = c.Write(append(handshake(765, "mc.example.net", 25565, StateLogin), 0x01, 0x00))
		held = append(held, c)
	}
	time.Sleep(100 * time.Millisecond)
	third, _ := net.Dial("tcp", addr)
	_, _ = third.Write(handshake(765, "mc.example.net", 25565, StateLogin))
	_ = third.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := third.Read(make([]byte, 8)); err == nil {
		t.Fatal("die dritte gleichzeitige Verbindung muss abgewiesen werden")
	}
	third.Close()
	for _, c := range held {
		c.Close()
	}
	if srv.Stats().RateLimited == 0 {
		t.Fatalf("Begrenzung nicht gezählt: %+v", srv.Stats())
	}
}

func TestNewConnectionRateLimitAllowsBurstsOfPlayers(t *testing.T) {
	be := newBackend(t, false)
	srv, addr := startGuard(t, func(c *Config) { c.NewConnPerSecond, c.NewConnBurst = 1, 5 }, be)
	ok, refused := 0, 0
	for i := 0; i < 12; i++ {
		if _, err := login(t, addr, "mc.example.net"); err == nil {
			ok++
		} else {
			refused++
		}
	}
	if ok < 5 || refused == 0 {
		t.Fatalf("Burst von 5 muss durchgehen, Überschuss nicht: ok=%d refused=%d", ok, refused)
	}
	_ = srv
}

func TestStatusPingAllowance(t *testing.T) {
	be := newBackend(t, false)
	srv, addr := startGuard(t, func(c *Config) { c.StatusPingsPerMinute = 2 }, be)
	ping := func() error {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return err
		}
		defer c.Close()
		_, _ = c.Write(append(handshake(765, "mc.example.net", 25565, StateStatus), 0x01, 0x00))
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, err = c.Read(make([]byte, 64))
		return err
	}
	if ping() != nil || ping() != nil {
		t.Fatal("die ersten zwei Pings müssen durchgehen")
	}
	if ping() == nil {
		t.Fatal("der dritte Ping in der Minute muss abgewiesen werden")
	}
	_ = srv
}

func TestAllowedHostsRejectIPScanners(t *testing.T) {
	be := newBackend(t, false)
	srv, addr := startGuard(t, func(c *Config) { c.AllowedHosts = []string{"mc.example.net"} }, be)
	if _, err := login(t, addr, "MC.Example.Net."); err != nil {
		t.Fatalf("erlaubter Hostname (andere Schreibweise): %v", err)
	}
	if _, err := login(t, addr, "203.0.113.9"); err == nil {
		t.Fatal("Verbindung per IP-Adresse muss abgewiesen werden")
	}
	if srv.Stats().Invalid != 1 {
		t.Fatalf("Invalid = %d", srv.Stats().Invalid)
	}
}

func TestSilentConnectionsAreDropped(t *testing.T) {
	be := newBackend(t, false)
	srv, addr := startGuard(t, nil, be)
	// 1. Connects and never sends a handshake.
	c, _ := net.Dial("tcp", addr)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("stille Verbindung muss geschlossen werden")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("Handshake-Timeout zu langsam: %v", time.Since(start))
	}
	c.Close()
	// 2. Sends only the handshake and then nothing.
	c2, _ := net.Dial("tcp", addr)
	_, _ = c2.Write(handshake(765, "mc.example.net", 25565, StateLogin))
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c2.Read(make([]byte, 1)); err == nil {
		t.Fatal("Verbindung ohne Folgedaten nach dem Handshake muss geschlossen werden")
	}
	c2.Close()
	time.Sleep(50 * time.Millisecond)
	if srv.Stats().Invalid != 2 || be.accepted.Load() != 0 {
		t.Fatalf("beide müssen als ungültig zählen und den Server nie erreichen: %+v", srv.Stats())
	}
}

func TestProxyProtocolCarriesTheRealPlayerAddress(t *testing.T) {
	be := newBackend(t, true)
	_, addr := startGuard(t, func(c *Config) { c.ProxyProtocol = true }, be)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	clientPort := c.LocalAddr().(*net.TCPAddr).Port
	pkt := append(handshake(765, "mc.example.net", 25565, StateLogin), 0x01, 0x00)
	_, _ = c.Write(pkt)
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = c.Read(make([]byte, 256))
	c.Close()

	got := be.firstBytes(0)
	if len(got) < 28 || !bytes.Equal(got[:12], proxyV2Signature) {
		t.Fatalf("PROXY-Header fehlt: %x", got)
	}
	if got[12] != 0x21 || got[13] != 0x11 || binary.BigEndian.Uint16(got[14:16]) != 12 {
		t.Fatalf("Kopf falsch: %x", got[12:16])
	}
	src := netip.AddrFrom4([4]byte(got[16:20]))
	if src != netip.MustParseAddr("127.0.0.1") || int(binary.BigEndian.Uint16(got[24:26])) != clientPort {
		t.Fatalf("Quelladresse/-port falsch: %v:%d, erwartet 127.0.0.1:%d", src, binary.BigEndian.Uint16(got[24:26]), clientPort)
	}
	if !bytes.Equal(got[28:], pkt) {
		t.Fatalf("hinter dem Header müssen die Client-Bytes folgen: %x", got[28:])
	}
}

func TestBackendDownIsCountedAndClientClosed(t *testing.T) {
	be := newBackend(t, false)
	be.ln.Close()
	srv, addr := startGuard(t, nil, be)
	if _, err := login(t, addr, "mc.example.net"); err == nil {
		t.Fatal("ohne erreichbaren Server muss der Client getrennt werden")
	}
	time.Sleep(50 * time.Millisecond)
	if srv.Stats().BackendFailures != 1 {
		t.Fatalf("BackendFailures = %d", srv.Stats().BackendFailures)
	}
}

func TestManyParallelPlayers(t *testing.T) {
	be := newBackend(t, false)
	srv, addr := startGuard(t, func(c *Config) { c.AllowCIDRs = []string{"127.0.0.0/8"} }, be)
	var wg sync.WaitGroup
	var failed atomic.Int64
	for i := 0; i < 300; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := login(t, addr, "mc.example.net"); err != nil {
				failed.Add(1)
			}
		}()
	}
	wg.Wait()
	if failed.Load() != 0 {
		t.Fatalf("%d von 300 gleichzeitigen Spielern scheiterten", failed.Load())
	}
	if srv.Stats().HandshakeOK != 300 {
		t.Fatalf("HandshakeOK = %d", srv.Stats().HandshakeOK)
	}
}

func TestConfigValidation(t *testing.T) {
	good := Config{Listen: "0.0.0.0:25565", Backend: "127.0.0.1:25566"}
	good.Defaults()
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Config){
		"stats öffentlich":  func(c *Config) { c.StatsListen = "0.0.0.0:9199" },
		"gleiche Adressen":  func(c *Config) { c.Backend = c.Listen },
		"Sperre zu lang":    func(c *Config) { c.BanSeconds = 999999 },
		"ungültiges CIDR":   func(c *Config) { c.AllowCIDRs = []string{"nope"} },
		"Backend ohne Port": func(c *Config) { c.Backend = "127.0.0.1" },
	} {
		c := good
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: wurde akzeptiert", name)
		}
	}
}
