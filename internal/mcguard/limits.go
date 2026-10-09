package mcguard

import (
	"net/netip"
	"sync"
	"time"
)

// source tracks one client address.
type source struct {
	tokens   float64
	last     time.Time
	conns    int
	pings    []time.Time
	invalid  []time.Time
	lastSeen time.Time
}

// limits holds per-source state and the ban list. One mutex is enough: every operation is a
// map lookup and a few arithmetic steps.
type limits struct {
	mu       sync.Mutex
	cfg      Config
	sources  map[netip.Addr]*source
	bans     map[netip.Addr]time.Time
	now      func() time.Time
	maxEntry int
}

func newLimits(cfg Config) *limits {
	return &limits{cfg: cfg, sources: map[netip.Addr]*source{}, bans: map[netip.Addr]time.Time{}, now: time.Now, maxEntry: 200000}
}

func (l *limits) get(a netip.Addr) *source {
	s := l.sources[a]
	if s == nil {
		s = &source{tokens: float64(l.cfg.NewConnBurst), last: l.now()}
		l.sources[a] = s
	}
	s.lastSeen = l.now()
	return s
}

// Banned reports whether a source is currently banned.
func (l *limits) Banned(a netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	until, ok := l.bans[a]
	if !ok {
		return false
	}
	if !l.now().Before(until) {
		delete(l.bans, a)
		return false
	}
	return true
}

// Admit decides whether a new connection from a may proceed. It returns a reason on refusal.
func (l *limits) Admit(a netip.Addr) (ok bool, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.sources) >= l.maxEntry {
		l.sweepLocked(0)
		if len(l.sources) >= l.maxEntry {
			return false, "tabelle voll" // a spoofed-source flood must not exhaust memory
		}
	}
	s := l.get(a)
	now := l.now()
	s.tokens += now.Sub(s.last).Seconds() * l.cfg.NewConnPerSecond
	if s.tokens > float64(l.cfg.NewConnBurst) {
		s.tokens = float64(l.cfg.NewConnBurst)
	}
	s.last = now
	if s.conns >= l.cfg.MaxPerSource {
		return false, "zu viele gleichzeitige Verbindungen"
	}
	if s.tokens < 1 {
		return false, "zu viele neue Verbindungen"
	}
	s.tokens--
	s.conns++
	return true, ""
}

// Release ends one admitted connection.
func (l *limits) Release(a netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if s := l.sources[a]; s != nil && s.conns > 0 {
		s.conns--
	}
}

// StatusPing counts a server-list ping and reports whether it is within the allowance.
func (l *limits) StatusPing(a netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.get(a)
	cut := l.now().Add(-time.Minute)
	kept := s.pings[:0]
	for _, t := range s.pings {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	s.pings = append(kept, l.now())
	return len(s.pings) <= l.cfg.StatusPingsPerMinute
}

// Invalid records a malformed handshake and bans the source after too many within the window.
// It returns true if the source was banned by this call.
func (l *limits) Invalid(a netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.get(a)
	now := l.now()
	cut := now.Add(-time.Duration(l.cfg.BanWindowSec) * time.Second)
	kept := s.invalid[:0]
	for _, t := range s.invalid {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	s.invalid = append(kept, now)
	if len(s.invalid) >= l.cfg.BanAfterInvalid {
		l.bans[a] = now.Add(time.Duration(l.cfg.BanSeconds) * time.Second)
		s.invalid = nil
		return true
	}
	return false
}

// Ban is one active ban.
type Ban struct {
	Addr  string    `json:"addr"`
	Until time.Time `json:"until"`
}

// Bans lists active bans, at most limit of them.
func (l *limits) Bans(limit int) []Ban {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	out := []Ban{}
	for a, until := range l.bans {
		if !now.Before(until) {
			delete(l.bans, a)
			continue
		}
		if len(out) < limit {
			out = append(out, Ban{Addr: a.String(), Until: until})
		}
	}
	return out
}

// Sweep drops state of sources that have been quiet for idle.
func (l *limits) Sweep(idle time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(idle)
}

func (l *limits) sweepLocked(idle time.Duration) {
	cut := l.now().Add(-idle)
	for a, s := range l.sources {
		if s.conns == 0 && !s.lastSeen.After(cut) {
			delete(l.sources, a)
		}
	}
}
