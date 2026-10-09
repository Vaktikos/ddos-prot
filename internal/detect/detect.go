// Package detect turns per-target packet counters into attack events.
//
// Each observation is a delta over one sampling interval. The engine combines
//   - absolute thresholds from the target's protection profile,
//   - an adaptive baseline (slow EWMA over quiet periods) that flags relative spikes,
//   - sliding-window persistence, so single-sample outliers never confirm an attack.
//
// Verdicts: a sustained absolute threshold breach is a confirmed attack; a sustained
// adaptive-only breach is a suspicious anomaly; short breaches are suspicious when
// they exceed an absolute threshold and plain traffic spikes otherwise.
package detect

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// Verdict classifies an event.
type Verdict string

const (
	VerdictSpike      Verdict = "traffic_spike"
	VerdictSuspicious Verdict = "suspicious_anomaly"
	VerdictConfirmed  Verdict = "confirmed_attack"
)

// Category names the traffic pattern that triggered an event.
type Category string

const (
	CategoryPacketFlood Category = "packet_flood"
	CategorySYNFlood    Category = "syn_flood"
	CategoryUDPFlood    Category = "udp_flood"
	CategoryICMPFlood   Category = "icmp_flood"
	// CategoryConnRate is a surge of new connection attempts to one service port.
	CategoryConnRate Category = "connection_rate"
	// CategoryFragFlood is a surge of IP fragments; CategoryInvalidFlags a surge of TCP
	// packets with impossible flag combinations.
	CategoryFragFlood    Category = "fragment_flood"
	CategoryInvalidFlags Category = "invalid_flags"
)

// Sample is a counter delta for one target over Interval.
type Sample struct {
	At       time.Time
	Interval time.Duration
	Packets  uint64
	Bytes    uint64
	SYN      uint64 // TCP packets with SYN set and ACK clear (new connection attempts)
	UDP      uint64
	ICMP     uint64
	Frag     uint64 // IP fragments
	Invalid  uint64 // TCP packets with invalid flag combinations
}

// Thresholds mirror the relevant fields of a protection profile.
type Thresholds struct {
	TotalPPS           float64
	SYNPPS             float64
	UDPPPS             float64
	ICMPPPS            float64
	ConnPPS            float64 // new connection attempts per second on one service
	FragPPS            float64
	InvalidPPS         float64
	BaselineMultiplier float64
	MinPPS             float64
	ConfirmSeconds     int
	ClearSeconds       int
}

// Event is one detected incident on a target.
type Event struct {
	ID         string    `json:"id"`
	Target     string    `json:"target"`
	Service    string    `json:"service,omitempty"` // e.g. "tcp/25565" for service-level events
	Category   Category  `json:"category"`
	Verdict    Verdict   `json:"verdict"`
	Started    time.Time `json:"started_at"`
	Ended      time.Time `json:"ended_at,omitempty"`
	PeakPPS    float64   `json:"peak_pps"`
	PeakBPS    float64   `json:"peak_bps"`
	PeakSYNPPS float64   `json:"peak_syn_pps"`
	PeakUDPPPS float64   `json:"peak_udp_pps"`
	PeakICMPPS float64   `json:"peak_icmp_pps"`
	Confidence float64   `json:"confidence"`
}

// Change is emitted when an event opens, escalates or closes.
type Change struct {
	Kind  string // "opened" | "escalated" | "closed"
	Event Event
}

// Tuning constants. They are deliberately conservative: a false positive
// blocks legitimate users, so the engine prefers late detection.
const (
	baselineAlpha     = 0.02 // EWMA weight of a quiet sample
	baselineWarmup    = 30   // samples before the adaptive rule is active
	sustainRatio      = 0.8  // fraction of window samples that must hit
	baselineClipMulti = 4    // quiet samples are clipped to 4x baseline before learning
)

type hit struct {
	at       time.Time
	abs      bool
	adaptive bool
}

type targetState struct {
	window     []hit
	baseline   float64
	baselineN  int
	active     *Event
	clearSince time.Time
}

// Engine holds detection state for all targets of one node. It is not safe for
// concurrent use; the agent drives it from a single goroutine.
type Engine struct {
	targets map[string]*targetState
	newID   func() string
}

// NewEngine creates an engine. newID may be nil to use random IDs.
func NewEngine(newID func() string) *Engine {
	if newID == nil {
		newID = randomID
	}
	return &Engine{targets: map[string]*targetState{}, newID: newID}
}

// Observe feeds one sample for a target and returns lifecycle changes.
func (e *Engine) Observe(target string, s Sample, th Thresholds) ([]Change, error) {
	if s.Interval <= 0 {
		return nil, fmt.Errorf("detect: Intervall für %s muss positiv sein", target)
	}
	if th.ConfirmSeconds < 1 || th.ClearSeconds < 1 {
		return nil, fmt.Errorf("detect: Bestätigungs- und Abklingzeit müssen >= 1s sein")
	}
	st := e.targets[target]
	if st == nil {
		st = &targetState{}
		e.targets[target] = st
	}
	sec := s.Interval.Seconds()
	pps := float64(s.Packets) / sec
	bps := float64(s.Bytes) * 8 / sec
	synPPS := float64(s.SYN) / sec
	udpPPS := float64(s.UDP) / sec
	icmpPPS := float64(s.ICMP) / sec

	abs, absCat := absoluteHit(th, rates{
		pps: pps, syn: synPPS, udp: udpPPS, icmp: icmpPPS,
		frag: float64(s.Frag) / sec, invalid: float64(s.Invalid) / sec,
	})
	adaptive := false
	if !abs && th.BaselineMultiplier > 0 && st.baselineN >= baselineWarmup {
		limit := st.baseline * th.BaselineMultiplier
		if th.MinPPS > limit {
			limit = th.MinPPS
		}
		adaptive = pps >= limit && pps > 0
	}

	st.window = append(st.window, hit{at: s.At, abs: abs, adaptive: adaptive})
	st.pruneWindow(s.At, th.ConfirmSeconds)
	verdict := st.classify(s.At, th.ConfirmSeconds, abs, adaptive)
	anyHit := abs || adaptive
	if !anyHit {
		st.learn(pps, th)
	}

	var changes []Change
	if verdict != "" {
		st.clearSince = time.Time{}
		if st.active == nil {
			ev := &Event{
				ID: e.newID(), Target: target, Category: st.eventCategory(absCat, abs),
				Verdict: verdict, Started: s.At,
			}
			st.active = ev
			st.updatePeaks(pps, bps, synPPS, udpPPS, icmpPPS, verdict)
			changes = append(changes, Change{Kind: "opened", Event: *ev})
		} else {
			prev := st.active.Verdict
			if rank(verdict) > rank(prev) {
				st.active.Verdict = verdict
				st.active.Category = st.eventCategory(absCat, abs)
				changes = append(changes, Change{Kind: "escalated", Event: *st.active})
			}
			st.updatePeaks(pps, bps, synPPS, udpPPS, icmpPPS, verdict)
		}
	} else if st.active != nil {
		if st.clearSince.IsZero() {
			st.clearSince = s.At
		}
		if s.At.Sub(st.clearSince) >= time.Duration(th.ClearSeconds)*time.Second {
			ev := *st.active
			ev.Ended = s.At
			st.active = nil
			st.clearSince = time.Time{}
			changes = append(changes, Change{Kind: "closed", Event: ev})
		}
	}
	return changes, nil
}

// Active returns a copy of the open event for a target, if any.
func (e *Engine) Active(target string) (Event, bool) {
	st := e.targets[target]
	if st == nil || st.active == nil {
		return Event{}, false
	}
	return *st.active, true
}

// Keys returns the keys of all targets the engine holds state for.
func (e *Engine) Keys() []string {
	out := make([]string, 0, len(e.targets))
	for k := range e.targets {
		out = append(out, k)
	}
	return out
}

// Forget drops all state for a target, for example after it was removed from policy.
// An open event is returned as closed at the given time.
func (e *Engine) Forget(target string, now time.Time) (Change, bool) {
	st := e.targets[target]
	delete(e.targets, target)
	if st == nil || st.active == nil {
		return Change{}, false
	}
	ev := *st.active
	ev.Ended = now
	return Change{Kind: "closed", Event: ev}, true
}

// rates are per-second values of one sample.
type rates struct{ pps, syn, udp, icmp, frag, invalid float64 }

func absoluteHit(th Thresholds, r rates) (bool, Category) {
	pps, syn, udp, icmp := r.pps, r.syn, r.udp, r.icmp
	switch {
	case th.InvalidPPS > 0 && r.invalid >= th.InvalidPPS:
		return true, CategoryInvalidFlags
	case th.FragPPS > 0 && r.frag >= th.FragPPS:
		return true, CategoryFragFlood
	case th.SYNPPS > 0 && syn >= th.SYNPPS && syn >= pps*0.5:
		return true, CategorySYNFlood
	case th.UDPPPS > 0 && udp >= th.UDPPPS:
		return true, CategoryUDPFlood
	case th.ICMPPPS > 0 && icmp >= th.ICMPPPS:
		return true, CategoryICMPFlood
	case th.TotalPPS > 0 && pps >= th.TotalPPS:
		return true, CategoryPacketFlood
	case th.ConnPPS > 0 && syn >= th.ConnPPS:
		// No SYN-ratio check: legitimate sessions with many packets are not new connections.
		return true, CategoryConnRate
	}
	return false, ""
}

func (st *targetState) pruneWindow(now time.Time, confirmSeconds int) {
	keep := time.Duration(confirmSeconds) * time.Second
	i := 0
	for i < len(st.window) && now.Sub(st.window[i].at) > keep {
		i++
	}
	if i > 0 {
		st.window = append(st.window[:0:0], st.window[i:]...)
	}
}

// sustainRatio returns the fraction of window entries with any hit.
func (st *targetState) sustainRatio() float64 {
	if len(st.window) == 0 {
		return 0
	}
	n := 0
	for _, h := range st.window {
		if h.abs || h.adaptive {
			n++
		}
	}
	return float64(n) / float64(len(st.window))
}

func (st *targetState) classify(now time.Time, confirmSeconds int, abs, adaptive bool) Verdict {
	n := len(st.window)
	if n == 0 {
		return ""
	}
	// The window is "full" once it spans confirmSeconds of observations.
	full := now.Sub(st.window[0].at) >= time.Duration(confirmSeconds-1)*time.Second
	absN, anyN := 0, 0
	for _, h := range st.window {
		if h.abs {
			absN++
		}
		if h.abs || h.adaptive {
			anyN++
		}
	}
	absRatio := float64(absN) / float64(n)
	anyRatio := float64(anyN) / float64(n)
	switch {
	case full && absRatio >= sustainRatio:
		return VerdictConfirmed
	case full && anyRatio >= sustainRatio:
		return VerdictSuspicious
	case abs:
		return VerdictSuspicious
	case adaptive:
		return VerdictSpike
	}
	return ""
}

func (st *targetState) learn(pps float64, th Thresholds) {
	ceiling := st.baseline * baselineClipMulti
	if th.MinPPS > ceiling {
		ceiling = th.MinPPS
	}
	if ceiling < 1 {
		ceiling = 1
	}
	v := pps
	if v > ceiling {
		v = ceiling
	}
	if st.baselineN == 0 {
		st.baseline = v
	} else {
		st.baseline = baselineAlpha*v + (1-baselineAlpha)*st.baseline
	}
	st.baselineN++
}

func (st *targetState) eventCategory(absCat Category, abs bool) Category {
	if abs {
		return absCat
	}
	return CategoryPacketFlood
}

func (st *targetState) updatePeaks(pps, bps, syn, udp, icmp float64, v Verdict) {
	ev := st.active
	ev.PeakPPS = max(ev.PeakPPS, pps)
	ev.PeakBPS = max(ev.PeakBPS, bps)
	ev.PeakSYNPPS = max(ev.PeakSYNPPS, syn)
	ev.PeakUDPPPS = max(ev.PeakUDPPPS, udp)
	ev.PeakICMPPS = max(ev.PeakICMPPS, icmp)
	ev.Confidence = confidence(v, st.sustainRatio())
}

// confidence is a documented heuristic, not a statistical probability:
// base score per verdict plus up to 0.1 for how consistently the window was hit.
func confidence(v Verdict, ratio float64) float64 {
	var base float64
	switch v {
	case VerdictConfirmed:
		base = 0.85
	case VerdictSuspicious:
		base = 0.45
	default:
		base = 0.15
	}
	c := base + 0.1*ratio
	if c > 0.99 {
		c = 0.99
	}
	return float64(int(c*100+0.5)) / 100
}

func rank(v Verdict) int {
	switch v {
	case VerdictConfirmed:
		return 3
	case VerdictSuspicious:
		return 2
	case VerdictSpike:
		return 1
	}
	return 0
}

func randomID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing means the system is unusable
	}
	return hex.EncodeToString(b)
}
