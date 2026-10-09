package agent

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"time"

	"github.com/vaktikos/ddos-prot/internal/mitigate"
	"github.com/vaktikos/ddos-prot/internal/netaddr"
)

// Owners of XDP block entries; they match the values used by the xdp package.
const (
	xdpOwnerManual = "manual"
	xdpOwnerAuto   = "auto"
)

const (
	// xdpSampleLimit bounds how many sources one sample returns, and so how many blocks one tick may add.
	xdpSampleLimit = 100
	xdpEventLimit  = 10 // sources listed in an event payload
)

// SourceRate is one source's measured rate toward protected destinations.
type SourceRate struct {
	Addr netip.Addr
	PPS  float64
	BPS  float64
}

// XDPStats are cumulative counters of the XDP filter.
type XDPStats struct {
	DroppedPackets, DroppedBytes, PassedPackets uint64
}

// XDPFilter is the early-drop filter. cmd/agent adapts the BPF implementation to it;
// tests use a fake. All methods must be safe to call from the agent goroutine only.
type XDPFilter interface {
	SetAllow([]netip.Prefix) error
	SetProtected([]netip.Prefix) error
	SetBlocks(owner string, want map[netip.Prefix]time.Time) error
	Block(p netip.Prefix, until time.Time, owner string) error
	Expire(now time.Time) int
	BlockCount() int
	Sample(now time.Time, minPPS float64, limit int) []SourceRate
	ResetBaseline()
	Stats() (XDPStats, error)
}

// SetXDP enables the XDP filter. Without it, plans that need XDP are reported as unavailable.
func (a *Agent) SetXDP(f XDPFilter) { a.xdp = f }

const panelAddrRefresh = 10 * time.Minute

// refreshPanelAddrs resolves the panel's address. Traffic from it must never be filtered,
// or a block could cut the agent off from its control plane.
func (a *Agent) refreshPanelAddrs(now time.Time) {
	u, err := url.Parse(a.cfg.PanelURL)
	if err != nil || u.Hostname() == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", u.Hostname())
	if err != nil || len(ips) == 0 {
		return // keep the previous addresses
	}
	a.panelAddrs = a.panelAddrs[:0]
	for _, ip := range ips {
		a.panelAddrs = append(a.panelAddrs, ip.Unmap())
	}
	a.panelAddrsAt = now
}

// syncXDP mirrors the policy into the filter: allowed sources, protected destinations and
// operator-approved blocks.
func (a *Agent) syncXDP() {
	if a.xdp == nil || a.pol == nil {
		return
	}
	var allow, protect []netip.Prefix
	allow = append(allow, a.mgmt...)
	a.refreshPanelAddrs(a.now())
	for _, ip := range a.panelAddrs {
		allow = append(allow, netip.PrefixFrom(ip, ip.BitLen()))
	}
	for _, s := range a.pol.Trusted {
		if p, err := netaddr.ParsePrefix(s); err == nil {
			allow = append(allow, p)
		}
	}
	for _, t := range a.pol.Targets {
		if p, err := netaddr.ParsePrefix(t.Prefix); err == nil {
			protect = append(protect, p)
		}
	}
	manual := map[netip.Prefix]time.Time{}
	for _, b := range a.pol.Blocks {
		if p, err := netaddr.ParsePrefix(b.Prefix); err == nil {
			manual[p] = b.ExpiresAt
		}
	}
	for label, err := range map[string]error{
		"allow":     a.xdp.SetAllow(allow),
		"protected": a.xdp.SetProtected(protect),
		"blocks":    a.xdp.SetBlocks(xdpOwnerManual, manual),
	} {
		if err != nil {
			a.setError(fmt.Sprintf("xdp %s: %v", label, err))
		}
	}
	a.clearError("xdp ")
}

// xdpPlans returns the applied plans that block sources in XDP.
func (a *Agent) xdpPlans() []mitigate.Plan {
	var out []mitigate.Plan
	for _, p := range mitigate.Applied(a.plans) {
		if p.Kind == mitigate.KindXDPBlock {
			out = append(out, p)
		}
	}
	return out
}

// stepXDP runs once per detection tick: it frees expired blocks, and while an XDP plan is
// active it blocks the strongest sources. It never blocks management, trusted or protected
// addresses, and it respects the policy's limit on dynamic entries.
func (a *Agent) stepXDP(now time.Time) {
	if a.xdp == nil || a.pol == nil {
		return
	}
	a.xdp.Expire(now)
	if now.Sub(a.panelAddrsAt) > panelAddrRefresh {
		a.refreshPanelAddrs(now)
		a.syncXDP()
	}
	plans := a.xdpPlans()
	if len(plans) == 0 {
		a.xdpActive = false
		return
	}
	if !a.xdpActive {
		a.xdpActive = true
		a.xdp.ResetBaseline() // the first sample after this only sets the baseline
		return
	}
	minPPS := plans[0].Rate
	block := time.Duration(plans[0].AutoBlockSeconds) * time.Second
	for _, p := range plans[1:] {
		if p.Rate < minPPS {
			minPPS = p.Rate
		}
		if d := time.Duration(p.AutoBlockSeconds) * time.Second; d > block {
			block = d
		}
	}
	maxBlocks := a.pol.Limits.MaxDynamicEntries
	if maxBlocks == 0 {
		maxBlocks = 4096
	}
	var blocked []string
	for _, r := range a.xdp.Sample(now, float64(minPPS), xdpSampleLimit) {
		if a.xdp.BlockCount() >= maxBlocks {
			a.emit("alert", "xdp_block_limit", map[string]any{"limit": maxBlocks})
			break
		}
		if a.neverBlock(r.Addr) {
			continue
		}
		pre := netip.PrefixFrom(r.Addr, r.Addr.BitLen())
		if err := a.xdp.Block(pre, now.Add(block), xdpOwnerAuto); err != nil {
			a.setError("xdp block: " + err.Error())
			continue
		}
		if len(blocked) < xdpEventLimit {
			blocked = append(blocked, fmt.Sprintf("%s (%.0f pps)", r.Addr, r.PPS))
		}
	}
	if len(blocked) > 0 {
		a.emit("mitigation", "xdp_blocked", map[string]any{"sources": blocked, "seconds": int(block.Seconds())})
	}
}

// neverBlock reports whether an address must be left alone: management and trusted networks,
// and the protected addresses themselves.
func (a *Agent) neverBlock(addr netip.Addr) bool {
	for _, p := range a.panelAddrs {
		if p == addr {
			return true
		}
	}
	for _, m := range a.mgmt {
		if m.Contains(addr) {
			return true
		}
	}
	for _, s := range a.pol.Trusted {
		if p, err := netaddr.ParsePrefix(s); err == nil && p.Contains(addr) {
			return true
		}
	}
	for _, t := range a.pol.Targets {
		if p, err := netaddr.ParsePrefix(t.Prefix); err == nil && p.Contains(addr) {
			return true
		}
	}
	return false
}
