package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/vaktikos/ddos-prot/internal/detect"
	"github.com/vaktikos/ddos-prot/internal/mcguard"
	"github.com/vaktikos/ddos-prot/internal/netaddr"
	"github.com/vaktikos/ddos-prot/internal/policy"
)

// GuardConfig names a Minecraft guard whose statistics the agent reads.
type GuardConfig struct {
	Name     string `json:"name"`
	StatsURL string `json:"stats_url"` // http://127.0.0.1:9199/stats; loopback only
	Target   string `json:"target"`    // protected prefix this guard fronts, e.g. 192.0.2.10
}

// GuardReport is the state of one guard as shown in the panel.
type GuardReport struct {
	Name          string  `json:"name"`
	Reachable     bool    `json:"reachable"`
	Active        int64   `json:"active"`
	HandshakeOKPS float64 `json:"handshake_ok_ps"`
	InvalidPS     float64 `json:"invalid_ps"`
	RateLimitedPS float64 `json:"rate_limited_ps"`
	BannedDropsPS float64 `json:"banned_drops_ps"`
	StatusPingsPS float64 `json:"status_pings_ps"`
	Bans          int     `json:"bans"`
	BansIssued    uint64  `json:"bans_issued"`
}

const (
	guardPollEvery = 2 * time.Second
	guardTimeout   = 400 * time.Millisecond
	// maxGuardMirror bounds how many guard bans are copied into XDP in one pass.
	maxGuardMirror = 500
)

type guardState struct {
	cfg      GuardConfig
	prev     *mcguard.StatsView
	prevAt   time.Time
	report   GuardReport
	mirrored map[netip.Prefix]time.Time
}

// validateGuards rejects guard settings that could make the agent contact anything but a local guard.
func validateGuards(gs []GuardConfig) error {
	var errs []error
	seen := map[string]bool{}
	for _, g := range gs {
		if g.Name == "" || seen[g.Name] {
			errs = append(errs, fmt.Errorf("minecraft_guards: name fehlt oder doppelt (%q)", g.Name))
		}
		seen[g.Name] = true
		u, err := url.Parse(g.StatsURL)
		if err != nil || u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") {
			errs = append(errs, fmt.Errorf("minecraft_guards %s: stats_url muss http://127.0.0.1:PORT/stats sein", g.Name))
		}
		if _, err := netaddr.ParsePrefix(g.Target); err != nil {
			errs = append(errs, fmt.Errorf("minecraft_guards %s: %w", g.Name, err))
		}
	}
	return errors.Join(errs...)
}

func (a *Agent) initGuards() {
	for _, g := range a.cfg.MinecraftGuards {
		a.guards = append(a.guards, &guardState{cfg: g, mirrored: map[netip.Prefix]time.Time{}})
	}
}

func fetchGuard(ctx context.Context, rawURL string) (*mcguard.StatsView, error) {
	ctx, cancel := context.WithTimeout(ctx, guardTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var v mcguard.StatsView
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&v); err != nil {
		return nil, err
	}
	return &v, nil
}

// stepGuards polls each guard every few seconds, derives rates, feeds protocol abuse into
// detection and mirrors the guards' bans into XDP.
func (a *Agent) stepGuards(now time.Time) {
	for _, g := range a.guards {
		if !g.prevAt.IsZero() && now.Sub(g.prevAt) < guardPollEvery {
			continue
		}
		cur, err := fetchGuard(context.Background(), g.cfg.StatsURL)
		if err != nil {
			g.report = GuardReport{Name: g.cfg.Name}
			a.setError("guard " + g.cfg.Name + " nicht erreichbar: " + err.Error())
			g.prev = nil
			continue
		}
		a.clearError("guard " + g.cfg.Name)
		dt := now.Sub(g.prevAt).Seconds()
		rep := GuardReport{Name: g.cfg.Name, Reachable: true, Active: cur.Active, Bans: len(cur.Bans), BansIssued: cur.BansIssued}
		if g.prev != nil && dt > 0 && cur.Accepted >= g.prev.Accepted {
			d := func(c, p uint64) float64 { return float64(c-p) / dt }
			rep.HandshakeOKPS = d(cur.HandshakeOK, g.prev.HandshakeOK)
			rep.InvalidPS = d(cur.Invalid, g.prev.Invalid)
			rep.RateLimitedPS = d(cur.RateLimited, g.prev.RateLimited)
			rep.BannedDropsPS = d(cur.BannedDrops, g.prev.BannedDrops)
			rep.StatusPingsPS = d(cur.StatusPings, g.prev.StatusPings)
			a.observeGuard(g, cur, now, time.Duration(dt*float64(time.Second)))
		}
		g.report, g.prev, g.prevAt = rep, cur, now
		a.mirrorGuardBans(g, cur, now)
	}
}

// observeGuard turns the guard's malformed-connection counters into detection events.
func (a *Agent) observeGuard(g *guardState, cur *mcguard.StatsView, now time.Time, dt time.Duration) {
	pre, err := netaddr.ParsePrefix(g.cfg.Target)
	if err != nil || a.pol == nil {
		return
	}
	prof := a.profileFor(pre.String())
	if prof.ProtocolAbusePPS <= 0 {
		return
	}
	abuse := (cur.Invalid - g.prev.Invalid) + (cur.BannedDrops - g.prev.BannedDrops)
	th := detect.Thresholds{AbusePPS: prof.ProtocolAbusePPS, ConfirmSeconds: prof.ConfirmSeconds, ClearSeconds: prof.ClearSeconds}
	key := fmt.Sprintf("%s|guard/%s", pre.String(), g.cfg.Name)
	changes, err := a.engine.Observe(key, detect.Sample{At: now, Interval: dt, Abuse: abuse}, th)
	if err != nil {
		a.setError("erkennung " + key + ": " + err.Error())
		return
	}
	for _, ch := range changes {
		a.handleChange(ch, now)
	}
}

// mirrorGuardBans copies the guard's active bans into the XDP filter, so banned sources are
// dropped before they reach the guard at all. It does nothing in dry-run mode, and it never
// blocks management, trusted, protected or panel addresses.
func (a *Agent) mirrorGuardBans(g *guardState, cur *mcguard.StatsView, now time.Time) {
	if a.xdp == nil || a.pol == nil || a.pol.Mode == policy.ModeDryRun {
		return
	}
	mirrored := 0
	for _, b := range cur.Bans {
		if mirrored >= maxGuardMirror {
			break
		}
		addr, err := netip.ParseAddr(b.Addr)
		if err != nil || !b.Until.After(now) || a.neverBlock(addr.Unmap()) {
			continue
		}
		pre := netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen())
		if until, ok := g.mirrored[pre]; ok && !until.Before(b.Until) {
			continue
		}
		if err := a.xdp.Block(pre, b.Until, xdpOwnerAuto); err != nil {
			a.setError("xdp guard-sperre: " + err.Error())
			continue
		}
		g.mirrored[pre] = b.Until
		mirrored++
	}
	if mirrored > 0 {
		a.emit("mitigation", "guard_bans_mirrored", map[string]any{"guard": g.cfg.Name, "count": mirrored})
	}
	for p, until := range g.mirrored { // forget expired bookkeeping
		if !until.After(now) {
			delete(g.mirrored, p)
		}
	}
}

func (a *Agent) guardReports() []GuardReport {
	out := make([]GuardReport, 0, len(a.guards))
	for _, g := range a.guards {
		out = append(out, g.report)
	}
	return out
}
