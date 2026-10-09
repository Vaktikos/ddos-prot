package mcguard

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vaktikos/ddos-prot/internal/netaddr"
)

// Stats are cumulative counters, safe to read while the guard runs.
type Stats struct {
	Accepted        atomic.Uint64
	HandshakeOK     atomic.Uint64
	Invalid         atomic.Uint64 // malformed handshakes, bad hosts, silent connections
	RateLimited     atomic.Uint64
	BannedDrops     atomic.Uint64
	StatusPings     atomic.Uint64
	Logins          atomic.Uint64
	BackendFailures atomic.Uint64
	BytesToServer   atomic.Uint64
	BytesToClient   atomic.Uint64
	Active          atomic.Int64
	BansIssued      atomic.Uint64
}

// StatsView is the JSON shape of the statistics endpoint.
type StatsView struct {
	Version         string `json:"version"`
	Active          int64  `json:"active"`
	Accepted        uint64 `json:"accepted"`
	HandshakeOK     uint64 `json:"handshake_ok"`
	Invalid         uint64 `json:"invalid"`
	RateLimited     uint64 `json:"rate_limited"`
	BannedDrops     uint64 `json:"banned_drops"`
	StatusPings     uint64 `json:"status_pings"`
	Logins          uint64 `json:"logins"`
	BackendFailures uint64 `json:"backend_failures"`
	BytesToServer   uint64 `json:"bytes_to_server"`
	BytesToClient   uint64 `json:"bytes_to_client"`
	BansIssued      uint64 `json:"bans_issued"`
	Bans            []Ban  `json:"bans"`
}

// Version of the guard, reported in its statistics.
const Version = "0.1.0"

// Server is the guard.
type Server struct {
	cfg   Config
	log   *slog.Logger
	lim   *limits
	st    Stats
	allow []netip.Prefix
	hosts map[string]bool
	wg    sync.WaitGroup
}

// New validates the configuration and prepares a server.
func New(cfg Config, log *slog.Logger) (*Server, error) {
	cfg.Defaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, log: log, lim: newLimits(cfg), hosts: map[string]bool{}}
	for _, c := range cfg.AllowCIDRs {
		p, err := netaddr.ParsePrefix(c)
		if err != nil {
			return nil, err
		}
		s.allow = append(s.allow, p)
	}
	for _, h := range cfg.AllowedHosts {
		s.hosts[strings.ToLower(strings.TrimSuffix(h, "."))] = true
	}
	return s, nil
}

// Stats returns a snapshot of the counters and the active bans.
func (s *Server) Stats() StatsView {
	return StatsView{
		Version: Version, Active: s.st.Active.Load(), Accepted: s.st.Accepted.Load(),
		HandshakeOK: s.st.HandshakeOK.Load(), Invalid: s.st.Invalid.Load(), RateLimited: s.st.RateLimited.Load(),
		BannedDrops: s.st.BannedDrops.Load(), StatusPings: s.st.StatusPings.Load(), Logins: s.st.Logins.Load(),
		BackendFailures: s.st.BackendFailures.Load(), BytesToServer: s.st.BytesToServer.Load(),
		BytesToClient: s.st.BytesToClient.Load(), BansIssued: s.st.BansIssued.Load(), Bans: s.lim.Bans(200),
	}
}

// StatsHandler serves /stats and /healthz. It must only be bound to loopback.
func (s *Server) StatsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /stats", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.Stats())
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	return mux
}

// Serve accepts connections until ctx ends or the listener fails.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	go s.sweepLoop(ctx)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				s.wg.Wait()
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.handle(conn) }()
	}
}

func (s *Server) sweepLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.lim.Sweep(5 * time.Minute)
		}
	}
}

func (s *Server) allowed(a netip.Addr) bool {
	for _, p := range s.allow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// reset closes with RST so a refused client does not linger in TIME_WAIT on our side.
func reset(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = c.Close()
}

func (s *Server) handle(client net.Conn) {
	s.st.Accepted.Add(1)
	ap, ok := client.RemoteAddr().(*net.TCPAddr)
	if !ok {
		_ = client.Close()
		return
	}
	addr := ap.AddrPort().Addr().Unmap()
	trusted := s.allowed(addr)

	if !trusted {
		if s.lim.Banned(addr) {
			s.st.BannedDrops.Add(1)
			reset(client) // no read, no parsing: a banned source costs almost nothing
			return
		}
		if s.st.Active.Load() >= int64(s.cfg.MaxConnections) {
			s.st.RateLimited.Add(1)
			reset(client)
			return
		}
		if ok, _ := s.lim.Admit(addr); !ok {
			s.st.RateLimited.Add(1)
			reset(client)
			return
		}
		defer s.lim.Release(addr)
	}
	s.st.Active.Add(1)
	defer s.st.Active.Add(-1)
	defer client.Close()

	br := bufio.NewReaderSize(client, 2048)
	_ = client.SetReadDeadline(time.Now().Add(s.cfg.handshakeTimeout()))
	hs, err := ReadHandshake(br)
	if err == nil && len(s.hosts) > 0 && !hs.Legacy && !s.hosts[hs.Host] {
		err = invalid("Hostname %q nicht erlaubt", hs.Host)
	}
	if err != nil {
		s.reject(addr, trusted, err)
		return
	}
	s.st.HandshakeOK.Add(1)

	if hs.State == StateStatus {
		s.st.StatusPings.Add(1)
		if !trusted && !s.lim.StatusPing(addr) {
			s.st.RateLimited.Add(1)
			return
		}
	} else {
		s.st.Logins.Add(1)
	}

	// After the handshake a real client sends its next packet within moments.
	// Legacy pings send everything at once and then wait, so they are exempt.
	if !hs.Legacy {
		_ = client.SetReadDeadline(time.Now().Add(s.cfg.idleAfterHandshake()))
		if _, err := br.Peek(1); err != nil && br.Buffered() == 0 {
			s.reject(addr, trusted, invalid("keine Daten nach dem Handshake"))
			return
		}
	}
	_ = client.SetReadDeadline(time.Time{})

	backend, err := net.DialTimeout("tcp", s.cfg.Backend, s.cfg.backendTimeout())
	if err != nil {
		s.st.BackendFailures.Add(1)
		return
	}
	defer backend.Close()
	if s.cfg.ProxyProtocol {
		// Source: the player. Destination: the address the player connected to.
		src := netip.AddrPortFrom(addr, ap.AddrPort().Port())
		local := client.LocalAddr().(*net.TCPAddr).AddrPort()
		dst := netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
		if _, err := backend.Write(ProxyHeaderV2(src, dst)); err != nil {
			s.st.BackendFailures.Add(1)
			return
		}
	}
	if _, err := backend.Write(hs.Raw); err != nil {
		return
	}
	s.st.BytesToServer.Add(uint64(len(hs.Raw)))

	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(backend, br)
		s.st.BytesToServer.Add(uint64(n))
		closeWrite(backend)
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(client, backend)
		s.st.BytesToClient.Add(uint64(n))
		closeWrite(client)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// reject counts a bad connection and bans repeat offenders. Trusted sources are never banned.
func (s *Server) reject(addr netip.Addr, trusted bool, err error) {
	s.st.Invalid.Add(1)
	if trusted {
		return
	}
	if s.lim.Invalid(addr) {
		s.st.BansIssued.Add(1)
		s.log.Info("quelle gesperrt", "addr", addr, "seconds", s.cfg.BanSeconds, "grund", err.Error())
	}
}
