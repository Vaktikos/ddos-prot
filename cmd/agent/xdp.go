package main

import (
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/vaktikos/ddos-prot/internal/agent"
	"github.com/vaktikos/ddos-prot/internal/xdp"
)

// xdpAdapter lets the agent use the BPF manager through its small interface.
type xdpAdapter struct{ m *xdp.Manager }

func (a xdpAdapter) SetAllow(p []netip.Prefix) error     { return a.m.SetAllow(p) }
func (a xdpAdapter) SetProtected(p []netip.Prefix) error { return a.m.SetProtected(p) }
func (a xdpAdapter) SetBlocks(owner string, w map[netip.Prefix]time.Time) error {
	return a.m.SetBlocks(owner, w)
}
func (a xdpAdapter) Block(p netip.Prefix, until time.Time, owner string) error {
	return a.m.Block(p, until, owner)
}
func (a xdpAdapter) Expire(now time.Time) int { return a.m.Expire(now) }
func (a xdpAdapter) BlockCount() int          { return a.m.BlockCount() }
func (a xdpAdapter) ResetBaseline()           { a.m.ResetBaseline() }
func (a xdpAdapter) Sample(now time.Time, minPPS float64, limit int) []agent.SourceRate {
	var out []agent.SourceRate
	for _, r := range a.m.Sample(now, minPPS, limit) {
		out = append(out, agent.SourceRate{Addr: r.Addr, PPS: r.PPS, BPS: r.BPS})
	}
	return out
}
func (a xdpAdapter) Stats() (agent.XDPStats, error) {
	s, err := a.m.Stats()
	return agent.XDPStats{DroppedPackets: s.DroppedPackets, DroppedBytes: s.DroppedBytes, PassedPackets: s.PassedPackets}, err
}

// enableXDP loads the filter and attaches it. A failure is logged and XDP stays off: the
// nftables protection does not depend on it.
func enableXDP(cfg agent.Config, a *agent.Agent, log *slog.Logger) (*xdp.Manager, error) {
	if len(cfg.XDPInterfaces) == 0 {
		return nil, nil
	}
	pinDir := ""
	if xdp.EnsureBPFFS("/sys/fs/bpf") {
		pinDir = cfg.XDPPinDir
		if err := mkdirAll(pinDir); err != nil {
			log.Warn("xdp: pin-verzeichnis nicht anlegbar, Filter endet mit dem Agent", "err", err)
			pinDir = ""
		}
	} else {
		log.Warn("xdp: bpffs nicht verfügbar, Filter endet mit dem Agent")
	}
	m, err := xdp.Load()
	if err != nil {
		return nil, fmt.Errorf("xdp laden: %w", err)
	}
	pinned, err := m.Attach(cfg.XDPInterfaces, cfg.XDPMode, pinDir)
	if err != nil {
		_ = m.Close()
		return nil, err
	}
	a.SetXDP(xdpAdapter{m})
	log.Info("xdp aktiv", "interfaces", cfg.XDPInterfaces, "mode", cfg.XDPMode, "pinned", pinned)
	return m, nil
}
