// Package policy defines the versioned protection policy that the control
// plane publishes to agents. A policy is validated before it is stored, signed
// by the panel, verified by the agent and validated again before it is applied.
package policy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/vaktikos/ddos-prot/internal/netaddr"
)

// Modes describe how far the agent may act on its own.
const (
	// ModeDryRun detects and records actions but never changes the firewall.
	ModeDryRun = "dry_run"
	// ModeApproval proposes mitigation; actions are applied only after an operator approves them.
	ModeApproval = "approval"
	// ModeAuto applies low-risk rate limits automatically. Blocks still need approval.
	ModeAuto = "auto"
)

// Protocols that can be declared as protected services.
const (
	ProtoTCP = "tcp"
	ProtoUDP = "udp"
)

// Policy is the complete desired state for one node.
type Policy struct {
	Version  int64              `json:"version"`
	NodeID   string             `json:"node_id"`
	Mode     string             `json:"mode"`
	IssuedAt time.Time          `json:"issued_at"`
	Targets  []Target           `json:"targets"`
	Profiles map[string]Profile `json:"profiles"`
	Trusted  []string           `json:"trusted"`
	Blocks   []ManualBlock      `json:"blocks"`
	Limits   Limits             `json:"limits"`
}

// Target is a protected IP address or network.
type Target struct {
	Name     string    `json:"name"`
	Prefix   string    `json:"prefix"`
	Profile  string    `json:"profile"`
	Services []Service `json:"services"`
}

// Service is a protected port on a target.
type Service struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
}

// Profile holds detection thresholds and mitigation preferences. Thresholds of
// zero disable the corresponding absolute signal.
type Profile struct {
	Kind string `json:"kind"` // generic | minecraft_java | minecraft_bedrock | web

	// Absolute thresholds, packets per second per target.
	TotalPPS float64 `json:"total_pps"`
	SYNPPS   float64 `json:"syn_pps"`
	UDPPPS   float64 `json:"udp_pps"`
	ICMPPPS  float64 `json:"icmp_pps"`
	// ConnPPS limits new connection attempts per second on a single service port.
	// Intended for game servers such as Minecraft, where normal traffic is mostly established packets.
	ConnPPS float64 `json:"conn_pps"`
	// FragPPS and InvalidPPS flag IP fragments and TCP packets with impossible flag
	// combinations (null, xmas, SYN+FIN, SYN+RST, FIN without ACK) per target.
	FragPPS    float64 `json:"frag_pps"`
	InvalidPPS float64 `json:"invalid_pps"`

	// Adaptive detection: a hit when pps >= max(MinPPS, baseline*BaselineMultiplier).
	BaselineMultiplier float64 `json:"baseline_multiplier"`
	MinPPS             float64 `json:"min_pps"`

	// Duration rules. An incident is confirmed after ConfirmSeconds of sustained hits
	// and closed after ClearSeconds without hits.
	ConfirmSeconds int `json:"confirm_seconds"`
	ClearSeconds   int `json:"clear_seconds"`

	Mitigation Mitigation `json:"mitigation"`
}

// Mitigation controls which automatic countermeasures a profile may use.
type Mitigation struct {
	// SYNRatePerSource limits SYN packets per source address per second to the
	// protected services of the target. Zero disables the rule.
	SYNRatePerSource int `json:"syn_rate_per_source"`
	// UDPRatePerSource limits UDP packets per source address per second. Zero disables the rule.
	UDPRatePerSource int `json:"udp_rate_per_source"`
	// AutoBlockSeconds, when positive, lets the kernel temporarily block sources that
	// exceed the per-source rates. Trusted and management addresses are always accepted first.
	AutoBlockSeconds int `json:"auto_block_seconds"`
	// DropFragments and DropInvalid allow dropping fragments / invalid TCP flag packets
	// toward the target while a matching incident is confirmed.
	DropFragments bool `json:"drop_fragments"`
	DropInvalid   bool `json:"drop_invalid"`
}

// ManualBlock is an operator-approved temporary block of a source prefix.
type ManualBlock struct {
	RuleID    string    `json:"rule_id"`
	Prefix    string    `json:"prefix"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Limits bound how much the agent may change at once.
type Limits struct {
	MaxActiveBlocks   int `json:"max_active_blocks"`
	MaxDynamicEntries int `json:"max_dynamic_entries"`
}

// Envelope is what an agent receives: the exact signed body plus its signature.
type Envelope struct {
	Version   int64  `json:"version"`
	Body      string `json:"body"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
}

// Canonical returns the deterministic JSON encoding used for hashing and signing.
func Canonical(p *Policy) ([]byte, error) {
	return json.Marshal(p)
}

// Digest returns the lowercase hex SHA-256 of a canonical body.
func Digest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// Sign signs the body with the panel's Ed25519 key and returns an envelope.
func Sign(priv ed25519.PrivateKey, p *Policy) (Envelope, error) {
	body, err := Canonical(p)
	if err != nil {
		return Envelope{}, err
	}
	sig := ed25519.Sign(priv, body)
	return Envelope{
		Version:   p.Version,
		Body:      string(body),
		SHA256:    Digest(body),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// Open verifies an envelope against the pinned panel public key and returns the
// decoded, validated policy. Nothing from the envelope is trusted before the
// signature check succeeds.
func Open(pub ed25519.PublicKey, env Envelope, mgmt []netip.Prefix) (*Policy, error) {
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		return nil, fmt.Errorf("signatur nicht dekodierbar: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, []byte(env.Body), sig) {
		return nil, errors.New("policy-signatur ungültig")
	}
	if Digest([]byte(env.Body)) != env.SHA256 {
		return nil, errors.New("policy-Prüfsumme stimmt nicht")
	}
	var p Policy
	dec := json.NewDecoder(strings.NewReader(env.Body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy nicht lesbar: %w", err)
	}
	if p.Version != env.Version {
		return nil, errors.New("policy-version im Envelope stimmt nicht überein")
	}
	if err := Validate(&p, mgmt); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks structure and safety constraints. mgmt lists management
// networks of the node; a policy that would block them is rejected.
func Validate(p *Policy, mgmt []netip.Prefix) error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if p.Version < 1 {
		add("version muss >= 1 sein")
	}
	switch p.Mode {
	case ModeDryRun, ModeApproval, ModeAuto:
	default:
		add("unbekannter Modus %q", p.Mode)
	}
	if p.Limits.MaxActiveBlocks < 0 || p.Limits.MaxActiveBlocks > 65535 {
		add("max_active_blocks außerhalb 0..65535")
	}
	if p.Limits.MaxDynamicEntries < 0 || p.Limits.MaxDynamicEntries > 1<<20 {
		add("max_dynamic_entries außerhalb 0..1048576")
	}

	for name, prof := range p.Profiles {
		errs = append(errs, validateProfile(name, prof)...)
	}

	var targets []netip.Prefix
	seen := map[string]bool{}
	for _, t := range p.Targets {
		pre, err := netaddr.ParsePrefix(t.Prefix)
		if err != nil {
			add("Ziel %q: %v", t.Name, err)
			continue
		}
		if err := netaddr.ValidateProtected(pre); err != nil {
			add("Ziel %q: %v", t.Name, err)
		}
		if seen[pre.String()] {
			add("Ziel %s ist mehrfach definiert", pre)
		}
		seen[pre.String()] = true
		if _, ok := p.Profiles[t.Profile]; !ok {
			add("Ziel %s verweist auf unbekanntes Profil %q", pre, t.Profile)
		}
		ports := map[string]bool{}
		for _, s := range t.Services {
			if s.Protocol != ProtoTCP && s.Protocol != ProtoUDP {
				add("Ziel %s: unbekanntes Protokoll %q", pre, s.Protocol)
			}
			if _, err := netaddr.ParsePort(int(s.Port)); err != nil {
				add("Ziel %s: %v", pre, err)
			}
			key := fmt.Sprintf("%s/%d", s.Protocol, s.Port)
			if ports[key] {
				add("Ziel %s: Dienst %s doppelt", pre, key)
			}
			ports[key] = true
		}
		targets = append(targets, pre)
	}

	var trusted []netip.Prefix
	for _, s := range p.Trusted {
		pre, err := netaddr.ParsePrefix(s)
		if err == nil {
			// A trusted source bypasses every block, so it must not be a catch-all network.
			err = netaddr.ValidateProtected(pre)
		}
		if err != nil {
			add("vertrauenswürdige Quelle: %v", err)
			continue
		}
		trusted = append(trusted, pre)
	}

	if len(p.Blocks) > p.Limits.MaxActiveBlocks && p.Limits.MaxActiveBlocks > 0 {
		add("%d manuelle Sperren überschreiten das Limit %d", len(p.Blocks), p.Limits.MaxActiveBlocks)
	}
	for _, b := range p.Blocks {
		pre, err := netaddr.ParsePrefix(b.Prefix)
		if err != nil {
			add("Sperre %s: %v", b.RuleID, err)
			continue
		}
		if err := netaddr.ValidateProtected(pre); err != nil {
			add("Sperre %s: %v", b.RuleID, err)
		}
		if b.ExpiresAt.IsZero() {
			add("Sperre %s: Ablaufzeit fehlt", pre)
		}
		for _, m := range mgmt {
			if netaddr.Overlaps(pre, m) {
				add("Sperre %s würde Management-Netz %s treffen", pre, m)
			}
		}
		for _, tr := range trusted {
			if netaddr.Overlaps(pre, tr) {
				add("Sperre %s widerspricht vertrauenswürdiger Quelle %s", pre, tr)
			}
		}
	}
	return errors.Join(errs...)
}

func validateProfile(name string, prof Profile) []error {
	var errs []error
	add := func(format string, a ...any) {
		errs = append(errs, fmt.Errorf("profil %q: "+format, append([]any{name}, a...)...))
	}
	switch prof.Kind {
	case "generic", "minecraft_java", "minecraft_bedrock", "web":
	default:
		add("unbekannte Art %q", prof.Kind)
	}
	for label, v := range map[string]float64{
		"total_pps": prof.TotalPPS, "syn_pps": prof.SYNPPS, "udp_pps": prof.UDPPPS,
		"icmp_pps": prof.ICMPPPS, "min_pps": prof.MinPPS, "conn_pps": prof.ConnPPS,
		"frag_pps": prof.FragPPS, "invalid_pps": prof.InvalidPPS,
	} {
		if v < 0 {
			add("%s darf nicht negativ sein", label)
		}
	}
	if prof.BaselineMultiplier != 0 && prof.BaselineMultiplier < 2 {
		add("baseline_multiplier muss 0 oder >= 2 sein")
	}
	if prof.ConfirmSeconds < 1 || prof.ConfirmSeconds > 300 {
		add("confirm_seconds muss zwischen 1 und 300 liegen")
	}
	if prof.ClearSeconds < 1 || prof.ClearSeconds > 900 {
		add("clear_seconds muss zwischen 1 und 900 liegen")
	}
	if prof.TotalPPS == 0 && prof.SYNPPS == 0 && prof.UDPPPS == 0 && prof.ICMPPPS == 0 && prof.ConnPPS == 0 && prof.FragPPS == 0 && prof.InvalidPPS == 0 && prof.BaselineMultiplier == 0 {
		add("mindestens ein Erkennungsschwellwert muss gesetzt sein")
	}
	m := prof.Mitigation
	if m.SYNRatePerSource < 0 || m.UDPRatePerSource < 0 || m.AutoBlockSeconds < 0 {
		add("Mitigations-Werte dürfen nicht negativ sein")
	}
	if m.AutoBlockSeconds > 86400 {
		add("auto_block_seconds darf höchstens 86400 sein")
	}
	return errs
}

// ValidateProfile checks one protection profile on its own. The panel uses it
// when a profile is created, so invalid thresholds never reach a node.
func ValidateProfile(name string, prof Profile) error {
	return errors.Join(validateProfile(name, prof)...)
}

// MaxBlockDays bounds how long a manual deny rule may last.
const MaxBlockDays = 30
