package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vaktikos/ddos-prot/internal/detect"
	"github.com/vaktikos/ddos-prot/internal/identity"
	"github.com/vaktikos/ddos-prot/internal/metrics"
	"github.com/vaktikos/ddos-prot/internal/mitigate"
	"github.com/vaktikos/ddos-prot/internal/netaddr"
	"github.com/vaktikos/ddos-prot/internal/nft"
	"github.com/vaktikos/ddos-prot/internal/policy"
)

// Version of the agent binary, reported to the panel.
const Version = "0.1.0"

const (
	maxOutbox = 5000
	// maxEventsPerHeartbeat keeps one request well below the panel's body limit,
	// so a backlog after an outage drains over several heartbeats instead of failing.
	maxEventsPerHeartbeat = 300
	// urgentMinGap bounds how often an incident change may trigger an immediate heartbeat.
	urgentMinGap = 5 * time.Second
)

// Ruleset is the firewall backend. nft.Applier implements it; tests use a fake.
type Ruleset interface {
	Apply(script string) error
	Counters() (map[string]nft.Counter, error)
	SetSize(set string) (int, error)
	Installed() bool
}

// HostSource returns cumulative host counters from the uplink interfaces.
type HostSource func() (HostCounters, error)

// HostCounters are raw cumulative values; the agent computes rates from them.
type HostCounters struct {
	Net metrics.NetCounters
	CPU metrics.CPUTimes
	Mem metrics.MemInfo
}

// Event is an entry in the outbox that is delivered to the panel with the next heartbeat.
type Event struct {
	ID      string    `json:"id"`
	Type    string    `json:"type"` // incident | mitigation | alert | policy
	Action  string    `json:"action"`
	At      time.Time `json:"at"`
	Payload any       `json:"payload"`
}

// Heartbeat is the status report sent to the panel.
type Heartbeat struct {
	AgentVersion         string          `json:"agent_version"`
	Hostname             string          `json:"hostname"`
	SentAt               time.Time       `json:"sent_at"`
	Mode                 string          `json:"mode"`
	AppliedPolicyVersion int64           `json:"applied_policy_version"`
	PolicyError          string          `json:"policy_error,omitempty"`
	Host                 HostReport      `json:"host"`
	Targets              []TargetReport  `json:"targets"`
	Mitigations          []mitigate.Plan `json:"mitigations"`
	DynamicEntries       int             `json:"dynamic_entries"`
	Health               Health          `json:"health"`
	Events               []Event         `json:"events"`
	DroppedEvents        uint64          `json:"dropped_events"`
}

// HostReport holds rates computed from /proc and the uplink counters.
type HostReport struct {
	CPUPercent   float64 `json:"cpu_percent"`
	MemUsedPct   float64 `json:"mem_used_percent"`
	RxBps        float64 `json:"rx_bps"`
	TxBps        float64 `json:"tx_bps"`
	RxPPS        float64 `json:"rx_pps"`
	TxPPS        float64 `json:"tx_pps"`
	RxDropsTotal uint64  `json:"rx_drops_total"`
	TxDropsTotal uint64  `json:"tx_drops_total"`
}

// TargetReport holds the last measured rates of one protected target.
type TargetReport struct {
	Prefix     string  `json:"prefix"`
	PPS        float64 `json:"pps"`
	BPS        float64 `json:"bps"`
	SYNPPS     float64 `json:"syn_pps"`
	UDPPPS     float64 `json:"udp_pps"`
	ICMPPPS    float64 `json:"icmp_pps"`
	DroppedPPS float64 `json:"dropped_pps"`
	Active     bool    `json:"active_incident"`
}

// Health summarizes the local state for operators.
type Health struct {
	Status string   `json:"status"` // ok | degraded
	Errors []string `json:"errors,omitempty"`
}

// HeartbeatReply carries the panel's instructions.
type HeartbeatReply struct {
	DesiredPolicyVersion int64     `json:"desired_policy_version"`
	ApprovedPlanIDs      []string  `json:"approved_plan_ids"`
	RejectedPlanIDs      []string  `json:"rejected_plan_ids"`
	ServerTime           time.Time `json:"server_time"`
}

// Agent holds all runtime state. It is driven by one goroutine (Run), so it needs no locks.
type Agent struct {
	cfg    Config
	log    *slog.Logger
	client *PanelClient
	store  Store
	nodeID string
	priv   ed25519.PrivateKey
	panel  ed25519.PublicKey
	mgmt   []netip.Prefix
	rules  Ruleset
	host   HostSource
	now    func() time.Time

	engine    *detect.Engine
	pol       *policy.Policy
	envelope  policy.Envelope
	applied   int64
	policyErr string
	plans     []mitigate.Plan
	outbox    []Event
	dropped   uint64
	errs      []string

	prevCounters map[string]nft.Counter
	prevAt       time.Time
	targets      map[string]TargetReport
	dynEntries   int
	host0        *HostCounters
	hostReport   HostReport
	hostAt       time.Time
	applyDirty   bool
	urgent       bool      // an incident changed; report before the next scheduled heartbeat
	lastUrgent   time.Time // rate limit for urgent heartbeats
}

// New loads the enrolled identity and prepares the agent. It does not touch the firewall.
func New(cfg Config, log *slog.Logger, rules Ruleset, host HostSource, client *PanelClient) (*Agent, error) {
	mgmt, err := cfg.ManagementPrefixes()
	if err != nil {
		return nil, err
	}
	st := Store{Dir: cfg.StateDir}
	nf, priv, pub, err := st.LoadNode()
	if err != nil {
		return nil, err
	}
	return &Agent{
		cfg: cfg, log: log, client: client, store: st,
		nodeID: nf.NodeID, priv: priv, panel: pub, mgmt: mgmt,
		rules: rules, host: host, now: time.Now,
		engine: detect.NewEngine(nil), targets: map[string]TargetReport{},
	}, nil
}

// Bootstrap adopts the cached policy so the node protects itself before the panel answers.
func (a *Agent) Bootstrap() {
	env, err := a.store.LoadEnvelope()
	if err != nil {
		a.policyErr = err.Error()
		a.log.Error("policy-cache nicht lesbar", "err", err)
		return
	}
	if env == nil {
		a.log.Info("keine gecachte Policy, warte auf erste Synchronisierung")
		return
	}
	if err := a.adopt(*env, "cache"); err != nil {
		a.policyErr = err.Error()
		a.log.Error("gecachte Policy abgelehnt", "err", err)
	}
}

// adopt verifies an envelope, makes it the desired state and renders the firewall.
// A rejected envelope leaves the previously applied state untouched.
func (a *Agent) adopt(env policy.Envelope, source string) error {
	p, err := policy.Open(a.panel, env, a.mgmt)
	if err != nil {
		return err
	}
	if p.NodeID != "" && p.NodeID != a.nodeID {
		return fmt.Errorf("policy gehört zu Node %s, nicht zu %s", p.NodeID, a.nodeID)
	}
	if err := a.store.SaveEnvelope(env); err != nil {
		return fmt.Errorf("policy-cache schreiben: %w", err)
	}
	prev := a.pol
	a.pol, a.envelope = p, env
	if prev != nil && p.Mode != prev.Mode {
		a.emit("policy", "mode_changed", map[string]string{"from": prev.Mode, "to": p.Mode})
	}
	if err := a.applyRules(a.now()); err != nil {
		a.pol = prev
		a.policyErr = err.Error()
		a.emit("policy", "apply_failed", map[string]any{"version": p.Version, "error": err.Error()})
		return fmt.Errorf("anwenden fehlgeschlagen: %w", err)
	}
	a.applied = p.Version
	a.policyErr = ""
	a.emit("policy", "applied", map[string]any{"version": p.Version, "source": source, "sha256": env.SHA256})
	a.log.Info("policy angewendet", "version", p.Version, "mode", p.Mode, "source", source)
	return nil
}

// applyRules renders the table from the current policy and active mitigations.
func (a *Agent) applyRules(now time.Time) error {
	if a.pol == nil {
		return nil
	}
	script, err := nft.Render(a.pol, a.mgmt, now, a.cfg.NftTable, a.activeMitigations())
	if err != nil {
		return err
	}
	if err := a.rules.Apply(script); err != nil {
		return err
	}
	a.prevCounters = nil // counters restart with the new table
	a.applyDirty = false
	return nil
}

func (a *Agent) activeMitigations() []nft.Active {
	var out []nft.Active
	for _, p := range mitigate.Applied(a.plans) {
		pre, err := netaddr.ParsePrefix(p.Target)
		if err != nil {
			continue
		}
		out = append(out, nft.Active{
			ID: p.ID, IncidentID: p.IncidentID, Kind: p.Kind, Target: pre,
			Rate: p.Rate, AutoBlockSeconds: p.AutoBlockSeconds,
		})
	}
	return out
}

// Tick runs one detection cycle: read counters, classify, decide mitigations.
func (a *Agent) Tick(now time.Time) {
	a.expireApprovals(now)
	a.sampleHost(now)
	if a.pol == nil {
		return
	}
	counters, err := a.rules.Counters()
	if err != nil {
		a.setError("zähler nicht lesbar: " + err.Error())
		return
	}
	a.clearError("zähler nicht lesbar")
	if a.prevCounters == nil {
		a.prevCounters, a.prevAt = counters, now
		return
	}
	dt := now.Sub(a.prevAt)
	if dt < 100*time.Millisecond {
		return
	}
	for i, t := range a.pol.Targets {
		pre, err := netaddr.ParsePrefix(t.Prefix)
		if err != nil {
			continue
		}
		key := pre.String()
		prof := a.pol.Profiles[t.Profile]
		base := fmt.Sprintf("t%d", i)
		sample := detect.Sample{
			At: now, Interval: dt,
			Packets: a.delta(counters, base+"_all", false),
			Bytes:   a.delta(counters, base+"_all", true),
			SYN:     a.delta(counters, base+"_syn", false),
			UDP:     a.delta(counters, base+"_udp", false),
			ICMP:    a.delta(counters, base+"_icmp", false),
		}
		dropped := a.delta(counters, base+"_rl", false)
		a.observeServices(counters, now, dt, pre, t, base, prof)
		changes, err := a.engine.Observe(key, sample, thresholdsOf(prof))
		if err != nil {
			a.setError("erkennung " + key + ": " + err.Error())
			continue
		}
		sec := dt.Seconds()
		_, active := a.engine.Active(key)
		a.targets[key] = TargetReport{
			Prefix: key, PPS: float64(sample.Packets) / sec, BPS: float64(sample.Bytes) * 8 / sec,
			SYNPPS: float64(sample.SYN) / sec, UDPPPS: float64(sample.UDP) / sec,
			ICMPPPS: float64(sample.ICMP) / sec, DroppedPPS: float64(dropped) / sec, Active: active,
		}
		for _, ch := range changes {
			a.handleChange(ch, now)
		}
	}
	a.prevCounters, a.prevAt = counters, now
	if a.applyDirty {
		if err := a.applyRules(now); err != nil {
			a.setError("mitigation anwenden: " + err.Error())
			a.emit("mitigation", "apply_failed", map[string]string{"error": err.Error()})
		} else {
			a.clearError("mitigation anwenden")
		}
	}
}

// observeServices runs connection-rate detection per protected TCP service port.
// Engine keys are "prefix|proto/port"; handleChange splits them again.
func (a *Agent) observeServices(counters map[string]nft.Counter, now time.Time, dt time.Duration, pre netip.Prefix, t policy.Target, base string, prof policy.Profile) {
	if prof.ConnPPS <= 0 {
		return
	}
	th := detect.Thresholds{ConnPPS: prof.ConnPPS, ConfirmSeconds: prof.ConfirmSeconds, ClearSeconds: prof.ClearSeconds}
	for j, svc := range t.Services {
		if svc.Protocol != policy.ProtoTCP {
			continue
		}
		sb := fmt.Sprintf("%s_s%d", base, j)
		key := fmt.Sprintf("%s|%s/%d", pre.String(), svc.Protocol, svc.Port)
		sample := detect.Sample{At: now, Interval: dt, SYN: a.delta(counters, sb+"_syn", false)}
		changes, err := a.engine.Observe(key, sample, th)
		if err != nil {
			a.setError("erkennung " + key + ": " + err.Error())
			continue
		}
		for _, ch := range changes {
			a.handleChange(ch, now)
		}
	}
}

func (a *Agent) delta(counters map[string]nft.Counter, name string, bytes bool) uint64 {
	cur, ok := counters[name]
	if !ok {
		return 0
	}
	prev := a.prevCounters[name]
	c, p := cur.Packets, prev.Packets
	if bytes {
		c, p = cur.Bytes, prev.Bytes
	}
	if c < p { // counter reset by a table re-apply
		return c
	}
	return c - p
}

func (a *Agent) handleChange(ch detect.Change, now time.Time) {
	ev := ch.Event
	if prefix, svc, ok := strings.Cut(ev.Target, "|"); ok {
		ev.Target, ev.Service = prefix, svc
	}
	ch.Event = ev
	a.emit("incident", ch.Kind, ev)
	a.urgent = true
	pre := a.profileFor(ev.Target)
	switch ch.Kind {
	case "opened", "escalated":
		if ev.Verdict != detect.VerdictConfirmed {
			return
		}
		d := mitigate.Decide(ev, pre, a.pol.Mode, a.dynEntries, a.pol.Limits.MaxDynamicEntries)
		if d.Escalate {
			a.emit("alert", "escalation", map[string]any{"incident_id": ev.ID, "target": ev.Target,
				"category": ev.Category, "peak_pps": ev.PeakPPS, "note": d.Note})
		}
		for _, p := range d.Plans {
			if a.hasPlan(p.ID) {
				continue
			}
			a.plans = append(a.plans, p)
			a.emit("mitigation", "proposed_"+p.Status, p)
			if p.Status == mitigate.StatusApplied {
				a.applyDirty = true
			}
		}
	case "closed":
		before := len(mitigate.Applied(a.plans))
		a.plans = mitigate.WithoutIncident(a.plans, ev.ID)
		if before != len(mitigate.Applied(a.plans)) {
			a.applyDirty = true
		}
	}
}

func (a *Agent) profileFor(target string) policy.Profile {
	for _, t := range a.pol.Targets {
		if p, err := netaddr.ParsePrefix(t.Prefix); err == nil && p.String() == target {
			return a.pol.Profiles[t.Profile]
		}
	}
	return policy.Profile{}
}

func (a *Agent) hasPlan(id string) bool {
	for _, p := range a.plans {
		if p.ID == id {
			return true
		}
	}
	return false
}

func (a *Agent) expireApprovals(now time.Time) {
	kept, expired := mitigate.ExpirePending(a.plans, now, time.Duration(a.cfg.ApprovalTimeoutS)*time.Second)
	if len(expired) > 0 {
		a.plans = kept
		for _, p := range expired {
			a.emit("mitigation", "approval_expired", p)
		}
	}
}

// sampleHost computes host rates from cumulative counters at most once per detection tick.
func (a *Agent) sampleHost(now time.Time) {
	if a.host == nil {
		return
	}
	cur, err := a.host()
	if err != nil {
		a.setError("host-metriken: " + err.Error())
		return
	}
	a.clearError("host-metriken")
	if a.host0 == nil {
		a.host0, a.hostAt = &cur, now
		return
	}
	dt := now.Sub(a.hostAt).Seconds()
	if dt <= 0 {
		return
	}
	prev := *a.host0
	a.hostReport = HostReport{
		CPUPercent:   metrics.CPUPercent(prev.CPU, cur.CPU),
		MemUsedPct:   cur.Mem.MemUsedPercent(),
		RxBps:        float64(cur.Net.RxBytes-prev.Net.RxBytes) * 8 / dt,
		TxBps:        float64(cur.Net.TxBytes-prev.Net.TxBytes) * 8 / dt,
		RxPPS:        float64(cur.Net.RxPackets-prev.Net.RxPackets) / dt,
		TxPPS:        float64(cur.Net.TxPackets-prev.Net.TxPackets) / dt,
		RxDropsTotal: cur.Net.RxDrops,
		TxDropsTotal: cur.Net.TxDrops,
	}
	a.host0, a.hostAt = &cur, now
}

// SyncPolicy downloads the desired policy when the panel announces a newer version.
func (a *Agent) SyncPolicy(ctx context.Context, desired int64) {
	if desired <= a.applied {
		return
	}
	env, err := a.client.FetchPolicy(ctx, a.nodeID, a.priv)
	if err != nil {
		a.policyErr = "abruf: " + err.Error()
		a.log.Warn("policy-abruf fehlgeschlagen, verwende letzte gültige Policy", "err", err)
		return
	}
	if err := a.adopt(env, "panel"); err != nil {
		a.policyErr = err.Error()
		a.emit("policy", "rejected", map[string]any{"version": env.Version, "error": err.Error()})
		a.log.Error("policy abgelehnt", "err", err)
		return
	}
}

// Heartbeat reports status and delivers the outbox. Events leave the outbox only
// after the panel acknowledged the heartbeat, so an outage never loses them.
// When a newer policy was applied during this exchange, the agent reports again at
// once, so the panel shows the new version without waiting for the next interval.
func (a *Agent) Heartbeat(ctx context.Context, now time.Time) error {
	reply, err := a.sendHeartbeat(ctx, now)
	if err != nil {
		a.log.Warn("heartbeat fehlgeschlagen, Schutz läuft lokal weiter", "err", err)
		return err
	}
	before := a.applied
	a.SyncPolicy(ctx, reply.DesiredPolicyVersion)
	if a.applied != before {
		if _, err := a.sendHeartbeat(ctx, a.now()); err != nil {
			a.log.Warn("bestätigungs-heartbeat fehlgeschlagen", "err", err)
		}
	}
	return nil
}

func (a *Agent) sendHeartbeat(ctx context.Context, now time.Time) (HeartbeatReply, error) {
	a.updateDynamicEntries()
	hostname, _ := os.Hostname()
	hb := Heartbeat{
		AgentVersion: Version, Hostname: hostname, SentAt: now,
		Mode: a.modeOrDefault(), AppliedPolicyVersion: a.applied, PolicyError: a.policyErr,
		Host: a.hostReport, Targets: a.targetList(), Mitigations: a.plans,
		DynamicEntries: a.dynEntries, Health: a.health(), Events: a.pendingEvents(),
		DroppedEvents: a.dropped,
	}
	reply, err := a.client.Heartbeat(ctx, a.nodeID, a.priv, hb)
	if err != nil {
		return reply, err
	}
	a.outbox = a.outbox[len(hb.Events):]
	a.applyDecisions(reply)
	return reply, nil
}

func (a *Agent) pendingEvents() []Event {
	n := len(a.outbox)
	if n > maxEventsPerHeartbeat {
		n = maxEventsPerHeartbeat
	}
	return append([]Event(nil), a.outbox[:n]...)
}

func (a *Agent) applyDecisions(reply HeartbeatReply) {
	for _, id := range reply.ApprovedPlanIDs {
		for i := range a.plans {
			if a.plans[i].ID == id && a.plans[i].Status == mitigate.StatusPendingApproval {
				a.plans[i].Status = mitigate.StatusApplied
				a.applyDirty = true
				a.emit("mitigation", "approved", a.plans[i])
			}
		}
	}
	for _, id := range reply.RejectedPlanIDs {
		before := len(a.plans)
		var kept []mitigate.Plan
		for _, p := range a.plans {
			if p.ID != id {
				kept = append(kept, p)
			}
		}
		if len(kept) != before {
			a.plans = kept
			a.emit("mitigation", "rejected", map[string]string{"id": id})
		}
	}
	if a.applyDirty {
		if err := a.applyRules(a.now()); err != nil {
			a.setError("freigabe anwenden: " + err.Error())
		} else {
			a.clearError("freigabe anwenden")
		}
	}
}

// Run drives detection and heartbeats until the context is cancelled.
// The panel being unreachable never stops detection or mitigation.
func (a *Agent) Run(ctx context.Context) error {
	a.Bootstrap()
	detectT := time.NewTicker(a.cfg.DetectInterval())
	defer detectT.Stop()
	hbT := time.NewTicker(a.cfg.HeartbeatInterval())
	defer hbT.Stop()
	_ = a.Heartbeat(ctx, a.now())
	for {
		select {
		case <-ctx.Done():
			return nil
		case t := <-detectT.C:
			a.Tick(t)
			if a.urgent && t.Sub(a.lastUrgent) >= urgentMinGap {
				a.urgent, a.lastUrgent = false, t
				_ = a.Heartbeat(ctx, t)
			}
		case t := <-hbT.C:
			_ = a.Heartbeat(ctx, t)
		}
	}
}

func (a *Agent) updateDynamicEntries() {
	total := 0
	for _, set := range []string{"dyn4", "dyn6"} {
		n, err := a.rules.SetSize(set)
		if err != nil {
			continue
		}
		total += n
	}
	a.dynEntries = total
}

func (a *Agent) modeOrDefault() string {
	if a.pol == nil {
		return "unconfigured"
	}
	return a.pol.Mode
}

func (a *Agent) targetList() []TargetReport {
	out := make([]TargetReport, 0, len(a.targets))
	if a.pol == nil {
		return out
	}
	for _, t := range a.pol.Targets {
		pre, err := netaddr.ParsePrefix(t.Prefix)
		if err != nil {
			continue
		}
		if r, ok := a.targets[pre.String()]; ok {
			out = append(out, r)
		}
	}
	return out
}

func (a *Agent) health() Health {
	h := Health{Status: "ok", Errors: append([]string(nil), a.errs...)}
	if a.policyErr != "" {
		h.Errors = append(h.Errors, "policy: "+a.policyErr)
	}
	if !a.rules.Installed() && a.pol != nil {
		h.Errors = append(h.Errors, "nftables-Tabelle nicht vorhanden")
	}
	if len(h.Errors) > 0 {
		h.Status = "degraded"
	}
	return h
}

func (a *Agent) setError(msg string) {
	for _, e := range a.errs {
		if e == msg {
			return
		}
	}
	a.errs = append(a.errs, msg)
}

func (a *Agent) clearError(prefix string) {
	var kept []string
	for _, e := range a.errs {
		if !strings.HasPrefix(e, prefix) {
			kept = append(kept, e)
		}
	}
	a.errs = kept
}

func (a *Agent) emit(typ, action string, payload any) {
	if len(a.outbox) >= maxOutbox {
		a.outbox = a.outbox[1:]
		a.dropped++
	}
	a.outbox = append(a.outbox, Event{ID: newID(), Type: typ, Action: action, At: a.now(), Payload: payload})
}

func thresholdsOf(p policy.Profile) detect.Thresholds {
	return detect.Thresholds{
		TotalPPS: p.TotalPPS, SYNPPS: p.SYNPPS, UDPPPS: p.UDPPPS, ICMPPPS: p.ICMPPPS, ConnPPS: 0,
		BaselineMultiplier: p.BaselineMultiplier, MinPPS: p.MinPPS,
		ConfirmSeconds: p.ConfirmSeconds, ClearSeconds: p.ClearSeconds,
	}
}

func newID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// Enroll creates the node identity and registers it with the panel using a one-time token.
func Enroll(ctx context.Context, cfg Config, token string, force bool) error {
	st := Store{Dir: cfg.StateDir}
	if _, err := os.Stat(filepath.Join(st.Dir, nodeFileName)); err == nil && !force {
		return errors.New("node ist bereits eingeschrieben (--force zum Überschreiben)")
	}
	client, err := NewPanelClient(cfg.PanelURL, cfg.CAFile)
	if err != nil {
		return err
	}
	pub, priv, err := identity.GenerateKey()
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	nf, err := client.Enroll(ctx, token, pub, hostname, Version)
	if err != nil {
		return fmt.Errorf("enrollment fehlgeschlagen: %w", err)
	}
	if err := identity.SaveKey(filepath.Join(st.Dir, identityFileName), priv); err != nil {
		return err
	}
	return st.SaveNode(nf)
}

func encodeB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// HostSampler reads cumulative counters from /proc for the given uplink interfaces.
// An empty list means every non-loopback interface.
func HostSampler(uplinks []string) HostSource {
	want := map[string]bool{}
	for _, u := range uplinks {
		want[u] = true
	}
	return func() (HostCounters, error) {
		var hc HostCounters
		netAll, err := metrics.ReadFile(metrics.ProcNetDev, metrics.ReadNetDev)
		if err != nil {
			return hc, err
		}
		for name, c := range netAll {
			if len(want) > 0 && !want[name] {
				continue
			}
			hc.Net.RxBytes += c.RxBytes
			hc.Net.RxPackets += c.RxPackets
			hc.Net.RxDrops += c.RxDrops
			hc.Net.TxBytes += c.TxBytes
			hc.Net.TxPackets += c.TxPackets
			hc.Net.TxDrops += c.TxDrops
		}
		if hc.CPU, err = metrics.ReadFile(metrics.ProcStat, metrics.ReadCPU); err != nil {
			return hc, err
		}
		if hc.Mem, err = metrics.ReadFile(metrics.ProcMem, metrics.ReadMem); err != nil {
			return hc, err
		}
		return hc, nil
	}
}
