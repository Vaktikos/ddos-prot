package netaddr

import (
	"net/netip"
	"testing"
)

func TestParsePrefix(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{"192.0.2.1", "192.0.2.1/32", false},
		{"192.0.2.77/24", "192.0.2.0/24", false},
		{"2001:db8::1", "2001:db8::1/128", false},
		{"2001:db8:abcd::/48", "2001:db8:abcd::/48", false},
		{"::ffff:192.0.2.5", "192.0.2.5/32", false},
		{"", "", true},
		{"example.com", "", true},
		{"192.0.2.0/33", "", true},
	}
	for _, c := range cases {
		got, err := ParsePrefix(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParsePrefix(%q): erwartete Fehler, erhielt %s", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePrefix(%q): unerwarteter Fehler: %v", c.in, err)
			continue
		}
		if got.String() != c.want {
			t.Errorf("ParsePrefix(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestValidateProtected(t *testing.T) {
	ok := []string{"192.0.2.1/32", "198.51.100.0/24", "2001:db8::/32"}
	bad := []string{"0.0.0.0/0", "10.0.0.0/4", "0.0.0.0/32", "224.0.0.1/32", "::/0", "ff02::1/128", "2001:db8::/8"}
	for _, s := range ok {
		p := netip.MustParsePrefix(s)
		if err := ValidateProtected(p); err != nil {
			t.Errorf("%s sollte gültig sein: %v", s, err)
		}
	}
	for _, s := range bad {
		p := netip.MustParsePrefix(s)
		if err := ValidateProtected(p); err == nil {
			t.Errorf("%s sollte abgelehnt werden", s)
		}
	}
}

func TestOverlapsFamilies(t *testing.T) {
	a := netip.MustParsePrefix("192.0.2.0/24")
	if !Overlaps(a, netip.MustParsePrefix("192.0.2.9/32")) {
		t.Error("erwartete Überlappung innerhalb IPv4")
	}
	if Overlaps(a, netip.MustParsePrefix("2001:db8::/32")) {
		t.Error("IPv4 und IPv6 dürfen nicht als überlappend gelten")
	}
}
