// Package mitigate decides which countermeasures a confirmed incident may trigger.
// It is pure logic: the agent applies the resulting plans through the nft package.
package mitigate

import (
	"fmt"
	"time"

	"github.com/vaktikos/ddos-prot/internal/detect"
	"github.com/vaktikos/ddos-prot/internal/nft"
	"github.com/vaktikos/ddos-prot/internal/policy"
)

// Statuses of a plan.
const (
	StatusProposed        = "proposed"         // dry-run: recorded, never applied
	StatusPendingApproval = "pending_approval" // waits for an operator
	StatusApplied         = "applied"          // active in the ruleset
)

// Plan is one countermeasure tied to exactly one incident.
type Plan struct {
	ID               string    `json:"id"`
	IncidentID       string    `json:"incident_id"`
	Kind             string    `json:"kind"`
	Target           string    `json:"target"`
	Rate             int       `json:"rate"`
	AutoBlockSeconds int       `json:"auto_block_seconds"`
	Status           string    `json:"status"`
	DryRun           bool      `json:"dry_run"`
	Reason           string    `json:"reason"`
	Proposed         time.Time `json:"proposed_at"`
}

// Decision is the outcome of evaluating one confirmed or suspicious event.
type Decision struct {
	Plans    []Plan
	Escalate bool   // notify administrators
	Note     string // human-readable summary for the audit trail
}

// Decide evaluates an event. Only confirmed attacks trigger countermeasures.
// dynUsed and dynMax describe the kernel set of temporary source blocks; when it
// is full, temporary blocks are withheld and only rate limits are used.
func Decide(ev detect.Event, prof policy.Profile, mode string, dynUsed, dynMax int) Decision {
	if ev.Verdict != detect.VerdictConfirmed {
		return Decision{Note: fmt.Sprintf("%s: keine Maßnahme (Stufe %s)", ev.Category, ev.Verdict)}
	}
	d := Decision{Escalate: true}

	var kind string
	var rate int
	switch ev.Category {
	case detect.CategorySYNFlood, detect.CategoryConnRate:
		// Connection surges are limited with the same per-source SYN rule. That rule
		// applies to all TCP services of the target, not only the attacked port.
		kind, rate = nft.KindSYNRate, prof.Mitigation.SYNRatePerSource
	case detect.CategoryUDPFlood:
		kind, rate = nft.KindUDPRate, prof.Mitigation.UDPRatePerSource
	case detect.CategoryFragFlood:
		if prof.Mitigation.DropFragments {
			kind, rate = nft.KindDropFrag, 1
		}
	case detect.CategoryInvalidFlags:
		if prof.Mitigation.DropInvalid {
			kind, rate = nft.KindDropInvalid, 1
		}
	default:
		d.Note = fmt.Sprintf("%s: keine automatische Maßnahme für diese Kategorie, Administratoren werden benachrichtigt", ev.Category)
		return d
	}
	if kind == "" || rate <= 0 {
		d.Note = fmt.Sprintf("%s: Profil erlaubt keine Ratenbegrenzung", ev.Category)
		return d
	}

	autoBlock := prof.Mitigation.AutoBlockSeconds
	if kind == nft.KindDropFrag || kind == nft.KindDropInvalid {
		autoBlock = 0 // these drop rules act on packet shape, not on sources
	}
	if autoBlock > 0 && dynUsed >= dynMax {
		autoBlock = 0
		d.Note = "Sperrliste voll: nur Ratenbegrenzung, keine zeitweisen Quellsperren"
	}

	status, dryRun := StatusApplied, false
	switch mode {
	case policy.ModeDryRun:
		status, dryRun = StatusProposed, true
	case policy.ModeApproval:
		status = StatusPendingApproval
	}

	reason := fmt.Sprintf("bestätigter %s, Spitze %.0f pps (SYN %.0f, UDP %.0f, ICMP %.0f)",
		ev.Category, ev.PeakPPS, ev.PeakSYNPPS, ev.PeakUDPPPS, ev.PeakICMPPS)
	d.Plans = []Plan{{
		ID:               fmt.Sprintf("%s-%s", ev.ID, kind),
		IncidentID:       ev.ID,
		Kind:             kind,
		Target:           ev.Target,
		Rate:             rate,
		AutoBlockSeconds: autoBlock,
		Status:           status,
		DryRun:           dryRun,
		Reason:           reason,
		Proposed:         ev.Started,
	}}
	if d.Note == "" {
		d.Note = fmt.Sprintf("%s: %s, Modus %s", kind, status, mode)
	}
	return d
}

// ExpirePending removes approval requests that were not answered in time.
// An unanswered request must never be applied later on stale evidence.
func ExpirePending(plans []Plan, now time.Time, timeout time.Duration) (kept, expired []Plan) {
	for _, p := range plans {
		if p.Status == StatusPendingApproval && now.Sub(p.Proposed) > timeout {
			expired = append(expired, p)
			continue
		}
		kept = append(kept, p)
	}
	return kept, expired
}

// WithoutIncident removes all plans of an incident, used when it closes.
func WithoutIncident(plans []Plan, incidentID string) []Plan {
	var kept []Plan
	for _, p := range plans {
		if p.IncidentID != incidentID {
			kept = append(kept, p)
		}
	}
	return kept
}

// Applied returns the plans that must be present in the ruleset right now.
func Applied(plans []Plan) []Plan {
	var out []Plan
	for _, p := range plans {
		if p.Status == StatusApplied && !p.DryRun {
			out = append(out, p)
		}
	}
	return out
}
