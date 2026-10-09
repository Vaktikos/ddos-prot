package agent

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"time"

	"github.com/vaktikos/ddos-prot/internal/detect"
	"github.com/vaktikos/ddos-prot/internal/l7"
	"github.com/vaktikos/ddos-prot/internal/mitigate"
	"github.com/vaktikos/ddos-prot/internal/netaddr"
)

// L7Config names a reverse-proxy reject log the agent follows.
type L7Config struct {
	Name   string `json:"name"`
	Path   string `json:"path"`   // absolute path of the ss_reject log
	Target string `json:"target"` // protected prefix the proxy fronts
}

// L7Source is one source in the report.
type L7Source struct {
	Addr string  `json:"addr"`
	RPS  float64 `json:"rps"`
}

// L7Report is the state of one followed log as shown in the panel.
type L7Report struct {
	Name         string     `json:"name"`
	Readable     bool       `json:"readable"`
	RejectedRPS  float64    `json:"rejected_rps"`
	Sources      int        `json:"sources"`
	Top          []L7Source `json:"top"`
	Unparsed     uint64     `json:"unparsed"`
	SkippedBytes uint64     `json:"skipped_bytes"`
	Blocked      int        `json:"blocked"`
}

const (
	l7WindowSeconds = 10
	l7TopSources    = 10
	l7MinInterval   = 500 * time.Millisecond
)

type l7State struct {
	cfg      L7Config
	tail     *l7.Tailer
	win      *l7.Window
	prevAt   time.Time
	unparsed uint64
	blocked  int
	banned   map[netip.Addr]time.Time
	report   L7Report
}

func validateL7(src []L7Config) error {
	var errs []error
	seen := map[string]bool{}
	for _, c := range src {
		if c.Name == "" || seen[c.Name] {
			errs = append(errs, fmt.Errorf("l7_sources: name fehlt oder doppelt (%q)", c.Name))
		}
		seen[c.Name] = true
		if !filepath.IsAbs(c.Path) {
			errs = append(errs, fmt.Errorf("l7_sources %s: path muss absolut sein", c.Name))
		}
		if _, err := netaddr.ParsePrefix(c.Target); err != nil {
			errs = append(errs, fmt.Errorf("l7_sources %s: %w", c.Name, err))
		}
	}
	return errors.Join(errs...)
}

func (a *Agent) initL7() {
	for _, c := range a.cfg.L7Sources {
		a.l7 = append(a.l7, &l7State{cfg: c, tail: l7.NewTailer(c.Path), win: l7.NewWindow(l7WindowSeconds), banned: map[netip.Addr]time.Time{}})
	}
}

func (a *Agent) l7Reports() []L7Report {
	out := make([]L7Report, 0, len(a.l7))
	for _, s := range a.l7 {
		out = append(out, s.report)
	}
	return out
}

// rejectedStatus reports whether a status was produced by a proxy rate limit. The ss_reject log
// is written only for rejected requests, but an operator may widen it; other statuses are ignored.
func rejectedStatus(code int) bool { return code == 429 || code == 503 || code == 444 }

// stepL7 reads the new log lines, feeds the rejected-request rate into detection and, while an
// l7_block_sources plan is applied, blocks sources that keep being rejected.
func (a *Agent) stepL7(now time.Time) {
	for _, s := range a.l7 {
		if !s.prevAt.IsZero() && now.Sub(s.prevAt) < l7MinInterval {
			continue
		}
		lines, err := s.tail.Poll()
		if err != nil {
			s.report = L7Report{Name: s.cfg.Name}
			a.setError("l7 " + s.cfg.Name + ": " + err.Error())
			s.prevAt = now
			continue
		}
		a.clearError("l7 " + s.cfg.Name)
		var rejected uint64
		for _, ln := range lines {
			e, ok := l7.ParseLine(ln)
			if !ok {
				s.unparsed++
				continue
			}
			if !rejectedStatus(e.Status) {
				continue
			}
			rejected++
			s.win.Add(now, e.Addr, 1)
		}
		dt := now.Sub(s.prevAt)
		first := s.prevAt.IsZero()
		s.prevAt = now
		if !first && a.pol != nil {
			a.observeL7(s, rejected, now, dt)
		}
		a.blockL7(s, now)
		s.report = a.l7Report(s, now)
	}
}

func (a *Agent) observeL7(s *l7State, rejected uint64, now time.Time, dt time.Duration) {
	pre, err := netaddr.ParsePrefix(s.cfg.Target)
	if err != nil {
		return
	}
	prof := a.profileFor(pre.String())
	if prof.HTTPRejectRPS <= 0 {
		return
	}
	th := detect.Thresholds{HTTPRPS: prof.HTTPRejectRPS, ConfirmSeconds: prof.ConfirmSeconds, ClearSeconds: prof.ClearSeconds}
	key := fmt.Sprintf("%s|l7/%s", pre.String(), s.cfg.Name)
	changes, err := a.engine.Observe(key, detect.Sample{At: now, Interval: dt, HTTP: rejected}, th)
	if err != nil {
		a.setError("erkennung " + key + ": " + err.Error())
		return
	}
	for _, ch := range changes {
		a.handleChange(ch, now)
	}
}

func (a *Agent) l7Plans(target string) []mitigate.Plan {
	var out []mitigate.Plan
	for _, p := range mitigate.Applied(a.plans) {
		if p.Kind == mitigate.KindL7Block && p.Target == target {
			out = append(out, p)
		}
	}
	return out
}

// blockL7 blocks sources whose rejected-request rate over the window reaches the plan's rate.
// It never blocks management, trusted, protected or panel addresses.
func (a *Agent) blockL7(s *l7State, now time.Time) {
	if a.xdp == nil || a.pol == nil {
		return
	}
	pre, err := netaddr.ParsePrefix(s.cfg.Target)
	if err != nil {
		return
	}
	plans := a.l7Plans(pre.String())
	if len(plans) == 0 {
		return
	}
	minRate, block := float64(plans[0].Rate), time.Duration(plans[0].AutoBlockSeconds)*time.Second
	_, per := s.win.Rates(now)
	maxBlocks := a.pol.Limits.MaxDynamicEntries
	if maxBlocks == 0 {
		maxBlocks = 4096
	}
	type srcRate struct {
		addr netip.Addr
		rps  float64
	}
	var strong []srcRate
	for addr, rps := range per {
		if rps >= minRate {
			strong = append(strong, srcRate{addr, rps})
		}
	}
	sort.Slice(strong, func(i, j int) bool { return strong[i].rps > strong[j].rps })
	for addr, until := range s.banned {
		if !until.After(now) {
			delete(s.banned, addr)
		}
	}
	var blocked []string
	for _, r := range strong {
		if a.xdp.BlockCount() >= maxBlocks {
			a.emit("alert", "xdp_block_limit", map[string]any{"limit": maxBlocks})
			break
		}
		if a.neverBlock(r.addr) {
			continue
		}
		if until, ok := s.banned[r.addr]; ok && until.After(now) {
			continue
		}
		if err := a.xdp.Block(netip.PrefixFrom(r.addr, r.addr.BitLen()), now.Add(block), xdpOwnerAuto); err != nil {
			a.setError("xdp block: " + err.Error())
			continue
		}
		s.banned[r.addr] = now.Add(block)
		s.blocked++
		if len(blocked) < xdpEventLimit {
			blocked = append(blocked, fmt.Sprintf("%s (%.0f req/s)", r.addr, r.rps))
		}
	}
	if len(blocked) > 0 {
		a.emit("mitigation", "l7_blocked", map[string]any{"sources": blocked, "seconds": int(block.Seconds()), "log": s.cfg.Name})
	}
}

func (a *Agent) l7Report(s *l7State, now time.Time) L7Report {
	total, per := s.win.Rates(now)
	top := make([]L7Source, 0, len(per))
	for addr, rps := range per {
		top = append(top, L7Source{Addr: addr.String(), RPS: rps})
	}
	sort.Slice(top, func(i, j int) bool { return top[i].RPS > top[j].RPS })
	if len(top) > l7TopSources {
		top = top[:l7TopSources]
	}
	return L7Report{Name: s.cfg.Name, Readable: true, RejectedRPS: total, Sources: len(per), Top: top,
		Unparsed: s.unparsed, SkippedBytes: s.tail.Skipped, Blocked: s.blocked}
}
