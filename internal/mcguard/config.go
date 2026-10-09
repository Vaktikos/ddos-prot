package mcguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/vaktikos/ddos-prot/internal/netaddr"
)

// Config is read from a JSON file. Defaults are deliberately generous: many players behind one
// NAT (schools, LAN events, mobile carriers) look like a single source address.
type Config struct {
	Listen  string `json:"listen"`  // public address, e.g. "0.0.0.0:25565"
	Backend string `json:"backend"` // the real server, e.g. "127.0.0.1:25566"
	// ProxyProtocol sends a PROXY protocol v2 header to the server. The server must be set
	// up to expect it (Paper: proxy-protocol, Velocity/BungeeCord: haproxy-protocol).
	ProxyProtocol bool `json:"proxy_protocol"`

	HandshakeTimeoutMS int `json:"handshake_timeout_ms"`
	IdleAfterHandshake int `json:"idle_after_handshake_ms"` // a login must follow soon after the handshake
	BackendTimeoutMS   int `json:"backend_timeout_ms"`

	MaxConnections       int     `json:"max_connections"`
	MaxPerSource         int     `json:"max_per_source"`
	NewConnPerSecond     float64 `json:"new_conn_per_second"` // sustained rate per source
	NewConnBurst         int     `json:"new_conn_burst"`
	StatusPingsPerMinute int     `json:"status_pings_per_minute"` // server-list pings per source

	BanAfterInvalid int `json:"ban_after_invalid"`
	BanWindowSec    int `json:"ban_window_seconds"`
	BanSeconds      int `json:"ban_seconds"`

	// AllowedHosts, if set, rejects handshakes for any other host name. This stops scanners
	// that connect by IP address. Leave empty to accept every name.
	AllowedHosts []string `json:"allowed_hosts"`
	// AllowCIDRs bypass all limits and bans (your own proxies, staff, monitoring).
	AllowCIDRs []string `json:"allow_cidrs"`

	StatsListen string `json:"stats_listen"` // loopback address for the JSON statistics
}

// LoadConfig reads, defaults and validates the file.
func LoadConfig(path string) (Config, error) {
	var c Config
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	c.Defaults()
	return c, c.Validate()
}

// Defaults fills unset values.
func (c *Config) Defaults() {
	setInt := func(v *int, d int) {
		if *v == 0 {
			*v = d
		}
	}
	setInt(&c.HandshakeTimeoutMS, 5000)
	setInt(&c.IdleAfterHandshake, 10000)
	setInt(&c.BackendTimeoutMS, 3000)
	setInt(&c.MaxConnections, 4000)
	setInt(&c.MaxPerSource, 30)
	setInt(&c.NewConnBurst, 30)
	setInt(&c.StatusPingsPerMinute, 60)
	setInt(&c.BanAfterInvalid, 5)
	setInt(&c.BanWindowSec, 60)
	setInt(&c.BanSeconds, 600)
	if c.NewConnPerSecond == 0 {
		c.NewConnPerSecond = 10
	}
	if c.StatsListen == "" {
		c.StatsListen = "127.0.0.1:9199"
	}
}

// Validate rejects values that would disable protection or open the statistics to the network.
func (c Config) Validate() error {
	var errs []error
	if _, err := netip.ParseAddrPort(c.Listen); err != nil {
		errs = append(errs, fmt.Errorf("listen muss host:port sein: %w", err))
	}
	if _, err := netip.ParseAddrPort(c.Backend); err != nil {
		errs = append(errs, fmt.Errorf("backend muss ip:port sein: %w", err))
	}
	if c.Listen == c.Backend {
		errs = append(errs, errors.New("listen und backend dürfen nicht gleich sein"))
	}
	if ap, err := netip.ParseAddrPort(c.StatsListen); err != nil || !ap.Addr().IsLoopback() {
		errs = append(errs, errors.New("stats_listen muss eine Loopback-Adresse sein, die Statistik ist nicht für das Netzwerk gedacht"))
	}
	if c.MaxConnections < 1 || c.MaxPerSource < 1 || c.NewConnBurst < 1 || c.NewConnPerSecond <= 0 {
		errs = append(errs, errors.New("Verbindungslimits müssen positiv sein"))
	}
	if c.BanAfterInvalid < 1 || c.BanWindowSec < 1 || c.BanSeconds < 1 || c.BanSeconds > 86400 {
		errs = append(errs, errors.New("Sperr-Werte außerhalb des erlaubten Bereichs (Sperre höchstens 86400 s)"))
	}
	if c.HandshakeTimeoutMS < 200 || c.HandshakeTimeoutMS > 60000 {
		errs = append(errs, errors.New("handshake_timeout_ms muss zwischen 200 und 60000 liegen"))
	}
	for _, s := range c.AllowCIDRs {
		if _, err := netaddr.ParsePrefix(s); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c Config) handshakeTimeout() time.Duration {
	return time.Duration(c.HandshakeTimeoutMS) * time.Millisecond
}
func (c Config) idleAfterHandshake() time.Duration {
	return time.Duration(c.IdleAfterHandshake) * time.Millisecond
}
func (c Config) backendTimeout() time.Duration {
	return time.Duration(c.BackendTimeoutMS) * time.Millisecond
}
