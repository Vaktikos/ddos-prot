// Package netaddr normalizes and validates IPv4/IPv6 addresses and CIDR prefixes.
package netaddr

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// MinPrefixV4 and MinPrefixV6 bound how broad a single protected or blocked
// prefix may be. Blocking a /0 or /4 would take down far more than an attack.
const (
	MinPrefixV4 = 8
	MinPrefixV6 = 16
)

// ParsePrefix accepts a single address ("192.0.2.1", "2001:db8::1") or a CIDR
// ("192.0.2.0/24") and returns it as a normalized netip.Prefix with host bits
// cleared. IPv4-mapped IPv6 addresses are unmapped.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, errors.New("leerer Adresswert")
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("ungültiges CIDR %q: %w", s, err)
		}
		if p.Addr().Is4In6() {
			return netip.Prefix{}, fmt.Errorf("IPv4-gemappte CIDR-Notation wird nicht unterstützt: %q", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("ungültige Adresse %q: %w", s, err)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// ValidateProtected checks a prefix that is used as a protected destination or
// trusted source. It rejects unspecified, multicast and overly broad prefixes.
func ValidateProtected(p netip.Prefix) error {
	a := p.Addr()
	switch {
	case !p.IsValid():
		return errors.New("ungültiges Präfix")
	case a.IsUnspecified():
		return fmt.Errorf("%s: unspezifizierte Adresse ist nicht erlaubt", p)
	case a.IsMulticast():
		return fmt.Errorf("%s: Multicast-Adressen sind nicht schützbar", p)
	case a.Is4() && p.Bits() < MinPrefixV4:
		return fmt.Errorf("%s: IPv4-Präfix ist zu breit (min. /%d)", p, MinPrefixV4)
	case a.Is6() && p.Bits() < MinPrefixV6:
		return fmt.Errorf("%s: IPv6-Präfix ist zu breit (min. /%d)", p, MinPrefixV6)
	}
	return nil
}

// Overlaps reports whether two prefixes share at least one address.
func Overlaps(a, b netip.Prefix) bool {
	if a.Addr().Is4() != b.Addr().Is4() {
		return false
	}
	return a.Overlaps(b)
}

// ParsePort validates a TCP/UDP port number in the range 1..65535.
func ParsePort(p int) (uint16, error) {
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("ungültiger Port %d", p)
	}
	return uint16(p), nil
}

// Family returns "ipv4" or "ipv6".
func Family(p netip.Prefix) string {
	if p.Addr().Is4() {
		return "ipv4"
	}
	return "ipv6"
}
