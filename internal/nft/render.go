// Package nft renders the Sentinel Shield nftables table from a validated policy
// and applies it atomically. The agent never builds firewall commands from
// strings received from the network: every value is validated as a netip.Prefix
// or an integer before it reaches the ruleset text.
package nft

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/vaktikos/ddos-prot/internal/netaddr"
	"github.com/vaktikos/ddos-prot/internal/policy"
)

// DefaultTable is the nftables table owned by Sentinel Shield. The agent only
// ever touches this table.
const DefaultTable = "sentinel_shield"

const defaultDynamicSize = 4096

// Render produces an nft script for the policy and the mitigations that are
// currently active. The script first declares the table (add + delete), which
// makes the replacement one atomic transaction and resets counters. mgmt lists
// networks that must never be dropped by Sentinel Shield. Mitigations exist only
// while their incident is open or their approval is valid; the policy merely
// bounds their parameters.
func Render(p *policy.Policy, mgmt []netip.Prefix, now time.Time, table string, active []Active) (string, error) {
	if err := policy.Validate(p, mgmt); err != nil {
		return "", fmt.Errorf("policy ungültig: %w", err)
	}
	if !validIdent(table) {
		return "", fmt.Errorf("ungültiger Tabellenname %q", table)
	}
	dynSize := p.Limits.MaxDynamicEntries
	if dynSize == 0 {
		dynSize = defaultDynamicSize
	}

	var counters, count, guard []string
	var trusted, mgmtSet []netip.Prefix
	for _, s := range p.Trusted {
		pre, err := netaddr.ParsePrefix(s)
		if err != nil {
			return "", err
		}
		trusted = append(trusted, pre)
	}
	mgmtSet = append(mgmtSet, mgmt...)

	// Counting: one named counter per target and per service, used for detection.
	for i, t := range p.Targets {
		pre, err := netaddr.ParsePrefix(t.Prefix)
		if err != nil {
			return "", err
		}
		d := daddr(pre)
		base := fmt.Sprintf("t%d", i)
		counters = append(counters, counterDecl(base+"_all"), counterDecl(base+"_syn"),
			counterDecl(base+"_udp"), counterDecl(base+"_icmp"), counterDecl(base+"_rl"),
			counterDecl(base+"_frag"), counterDecl(base+"_inv"))
		count = append(count,
			fmt.Sprintf(`%s counter name "%s_all"`, d, base),
			fmt.Sprintf(`%s tcp flags & (fin | syn | rst | ack) == syn counter name "%s_syn"`, d, base),
			fmt.Sprintf(`%s meta l4proto udp counter name "%s_udp"`, d, base),
			fmt.Sprintf(`%s meta l4proto { icmp, icmpv6 } counter name "%s_icmp"`, d, base),
			fmt.Sprintf(`%s %s counter name "%s_frag"`, d, fragMatch(pre), base),
		)
		for _, m := range invalidFlagMatches {
			count = append(count, fmt.Sprintf(`%s %s counter name "%s_inv"`, d, m, base))
		}
		for j, s := range t.Services {
			sc := fmt.Sprintf("%s_s%d", base, j)
			counters = append(counters, counterDecl(sc+"_pkts"))
			count = append(count, fmt.Sprintf(`%s %s dport %d counter name "%s_pkts"`, d, s.Protocol, s.Port, sc))
			if s.Protocol == policy.ProtoTCP {
				counters = append(counters, counterDecl(sc+"_syn"))
				count = append(count, fmt.Sprintf(`%s tcp dport %d tcp flags & (fin | syn | rst | ack) == syn counter name "%s_syn"`, d, s.Port, sc))
			}
		}
	}

	// Guard: accept management and trusted first, then drop manual and dynamic
	// blocks, then apply per-source rate limits to the protected targets.
	guard = append(guard, setMatchAccept("trusted")...)
	guard = append(guard, setMatchAccept("mgmt")...)
	blk4, blk6 := splitBlocks(p.Blocks, now)
	guard = append(guard,
		"ip saddr @blk4 counter name \"blk_drop4\" drop",
		"ip6 saddr @blk6 counter name \"blk_drop6\" drop",
		"ip saddr @dyn4 counter name \"dyn_drop4\" drop",
		"ip6 saddr @dyn6 counter name \"dyn_drop6\" drop",
	)
	counters = append(counters, counterDecl("blk_drop4"), counterDecl("blk_drop6"),
		counterDecl("dyn_drop4"), counterDecl("dyn_drop6"))

	indexOf := map[string]int{}
	for i, t := range p.Targets {
		pre, err := netaddr.ParsePrefix(t.Prefix)
		if err != nil {
			return "", err
		}
		indexOf[pre.String()] = i
	}
	for _, a := range active {
		i, ok := indexOf[a.Target.String()]
		if !ok {
			return "", fmt.Errorf("aktive Maßnahme %s verweist auf kein Ziel der Policy", a.ID)
		}
		t := p.Targets[i]
		if err := a.validate(); err != nil {
			return "", err
		}
		base := fmt.Sprintf("t%d", i)
		c := fmt.Sprintf(`comment "%s"`, a.IncidentID)
		switch a.Kind {
		case KindSYNRate:
			ports := tcpPorts(t)
			if len(ports) == 0 {
				guard = append(guard, rateRule(a.Target, base+"_tcp", "tcp flags & (fin | syn | rst | ack) == syn", a.Rate, a.AutoBlockSeconds, base, c))
			}
			for _, port := range ports {
				guard = append(guard, rateRule(a.Target, fmt.Sprintf("%s_tcp%d", base, port),
					fmt.Sprintf("tcp dport %d tcp flags & (fin | syn | rst | ack) == syn", port), a.Rate, a.AutoBlockSeconds, base, c))
			}
		case KindDropFrag:
			guard = append(guard, fmt.Sprintf(`%s %s counter name "%s_rl" drop %s`, daddr(a.Target), fragMatch(a.Target), base, c))
		case KindDropInvalid:
			for _, m := range invalidFlagMatches {
				guard = append(guard, fmt.Sprintf(`%s %s counter name "%s_rl" drop %s`, daddr(a.Target), m, base, c))
			}
		case KindUDPRate:
			ports := udpPorts(t)
			if len(ports) == 0 {
				guard = append(guard, rateRule(a.Target, base+"_udp", "meta l4proto udp", a.Rate, a.AutoBlockSeconds, base, c))
			}
			for _, port := range ports {
				guard = append(guard, rateRule(a.Target, fmt.Sprintf("%s_udp%d", base, port),
					fmt.Sprintf("udp dport %d", port), a.Rate, a.AutoBlockSeconds, base, c))
			}
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Sentinel Shield ruleset, generated %s\n", now.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "add table inet %s\n", table)
	fmt.Fprintf(&b, "delete table inet %s\n", table)
	fmt.Fprintf(&b, "table inet %s {\n", table)
	for _, c := range counters {
		fmt.Fprintf(&b, "\t%s\n", c)
	}
	writeSet(&b, "trusted4", "ipv4_addr", "interval", prefixesOf(trusted, 4), nil)
	writeSet(&b, "trusted6", "ipv6_addr", "interval", prefixesOf(trusted, 6), nil)
	writeSet(&b, "mgmt4", "ipv4_addr", "interval", prefixesOf(mgmtSet, 4), nil)
	writeSet(&b, "mgmt6", "ipv6_addr", "interval", prefixesOf(mgmtSet, 6), nil)
	writeSet(&b, "blk4", "ipv4_addr", "interval,timeout", nil, blk4)
	writeSet(&b, "blk6", "ipv6_addr", "interval,timeout", nil, blk6)
	fmt.Fprintf(&b, "\tset dyn4 { type ipv4_addr; flags dynamic,timeout; size %d; }\n", dynSize)
	fmt.Fprintf(&b, "\tset dyn6 { type ipv6_addr; flags dynamic,timeout; size %d; }\n", dynSize)
	fmt.Fprintf(&b, "\tchain count {\n\t\ttype filter hook prerouting priority -310; policy accept;\n")
	for _, r := range count {
		fmt.Fprintf(&b, "\t\t%s\n", r)
	}
	fmt.Fprintf(&b, "\t}\n")
	fmt.Fprintf(&b, "\tchain guard {\n\t\ttype filter hook prerouting priority -300; policy accept;\n")
	for _, r := range guard {
		fmt.Fprintf(&b, "\t\t%s\n", r)
	}
	fmt.Fprintf(&b, "\t}\n}\n")
	return b.String(), nil
}

// Mitigation kinds that can be active on a target.
const (
	KindSYNRate = "syn_rate_limit"
	KindUDPRate = "udp_rate_limit"
	// KindDropFrag drops IP fragments toward a target; KindDropInvalid drops TCP packets
	// with impossible flag combinations. Neither needs a rate.
	KindDropFrag    = "drop_fragments"
	KindDropInvalid = "drop_invalid_flags"
)

// invalidFlagMatches are TCP flag combinations that no correct stack sends: null scan,
// SYN+FIN, SYN+RST, xmas and FIN without ACK.
var invalidFlagMatches = []string{
	"tcp flags & (fin | syn | rst | psh | ack | urg) == 0",
	"tcp flags & (fin | syn) == fin | syn",
	"tcp flags & (syn | rst) == syn | rst",
	"tcp flags & (fin | psh | urg) == fin | psh | urg",
	"tcp flags & (fin | ack) == fin",
}

// fragMatch matches any IP fragment (IPv4: more-fragments flag or offset; IPv6: fragment header).
func fragMatch(p netip.Prefix) string {
	if p.Addr().Is4() {
		return "ip frag-off & 0x3fff != 0"
	}
	return "exthdr frag exists"
}

// Active is one mitigation that the ruleset must currently contain.
type Active struct {
	ID               string
	IncidentID       string
	Kind             string
	Target           netip.Prefix
	Rate             int // packets per second per source before limiting
	AutoBlockSeconds int // 0 = limit only, no temporary source block
}

func (a Active) validate() error {
	switch a.Kind {
	case KindSYNRate, KindUDPRate:
		if a.Rate < 1 || a.Rate > 1000000 {
			return fmt.Errorf("Maßnahme %s: Rate außerhalb 1..1000000", a.ID)
		}
	case KindDropFrag, KindDropInvalid:
	default:
		return fmt.Errorf("unbekannte Maßnahme %q", a.Kind)
	}
	if a.AutoBlockSeconds < 0 || a.AutoBlockSeconds > 86400 {
		return fmt.Errorf("Maßnahme %s: Sperrdauer außerhalb 0..86400", a.ID)
	}
	if !validIdent(a.IncidentID) {
		return fmt.Errorf("Maßnahme %s: ungültige Vorfalls-ID", a.ID)
	}
	return nil
}

func counterDecl(name string) string { return fmt.Sprintf("counter %s { }", name) }

func daddr(p netip.Prefix) string {
	if p.Addr().Is4() {
		return "ip daddr " + p.String()
	}
	return "ip6 daddr " + p.String()
}

func saddrKey(p netip.Prefix) string {
	if p.Addr().Is4() {
		return "ip saddr"
	}
	return "ip6 saddr"
}

// setMatchAccept emits the accept rules for a named pair of address sets (IPv4 and IPv6).
func setMatchAccept(name string) []string {
	return []string{fmt.Sprintf("ip saddr @%s4 accept", name), fmt.Sprintf("ip6 saddr @%s6 accept", name)}
}

func rateRule(target netip.Prefix, label, match string, rate, blockSeconds int, counter, comment string) string {
	meter := "ss_" + sanitize(label)
	src := saddrKey(target)
	dyn := "dyn4"
	if !target.Addr().Is4() {
		dyn = "dyn6"
	}
	addStmt := ""
	if blockSeconds > 0 {
		addStmt = fmt.Sprintf(" add @%s { %s timeout %ds }", dyn, src, blockSeconds)
	}
	return fmt.Sprintf(`%s %s meter %s { %s timeout 60s limit rate over %d/second }%s counter name "%s_rl" drop %s`,
		daddr(target), match, meter, src, rate, addStmt, counter, comment)
}

// splitBlocks returns the unexpired manual blocks per family, sorted for stable output.
func splitBlocks(blocks []policy.ManualBlock, now time.Time) (v4, v6 []elem) {
	for _, b := range blocks {
		pre, err := netaddr.ParsePrefix(b.Prefix)
		if err != nil {
			continue
		}
		remaining := b.ExpiresAt.Sub(now)
		if remaining < time.Second {
			continue // expired blocks are dropped from the ruleset
		}
		e := elem{prefix: pre, seconds: int64(remaining.Seconds())}
		if pre.Addr().Is4() {
			v4 = append(v4, e)
		} else {
			v6 = append(v6, e)
		}
	}
	sortElems(v4)
	sortElems(v6)
	return v4, v6
}

type elem struct {
	prefix  netip.Prefix
	seconds int64
}

func sortElems(e []elem) {
	sort.Slice(e, func(i, j int) bool { return e[i].prefix.String() < e[j].prefix.String() })
}

func writeSet(b *strings.Builder, name, typ, flags string, prefixes []netip.Prefix, timed []elem) {
	var parts []string
	for _, p := range prefixes {
		parts = append(parts, p.String())
	}
	for _, e := range timed {
		parts = append(parts, fmt.Sprintf("%s timeout %ds", e.prefix, e.seconds))
	}
	fmt.Fprintf(b, "\tset %s { type %s; flags %s;", name, typ, flags)
	if len(parts) > 0 {
		fmt.Fprintf(b, " elements = { %s };", strings.Join(parts, ", "))
	}
	fmt.Fprintf(b, " }\n")
}

func prefixesOf(ps []netip.Prefix, family int) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range ps {
		if (family == 4) == p.Addr().Is4() {
			out = append(out, p)
		}
	}
	return out
}

func tcpPorts(t policy.Target) []uint16 { return portsOf(t, policy.ProtoTCP) }
func udpPorts(t policy.Target) []uint16 { return portsOf(t, policy.ProtoUDP) }

func portsOf(t policy.Target, proto string) []uint16 {
	var out []uint16
	for _, s := range t.Services {
		if s.Protocol == proto {
			out = append(out, s.Port)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

func validIdent(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	return sanitize(s) == s
}
