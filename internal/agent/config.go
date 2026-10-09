// Package agent implements the Sentinel Shield protection agent: local
// measurement, detection and mitigation, plus a signed control channel to the panel.
// The agent keeps protecting with its last verified policy if the panel is unreachable.
package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/vaktikos/ddos-prot/internal/netaddr"
)

// Config is the agent's local configuration, read from /etc/sentinel-shield/agent.json.
type Config struct {
	PanelURL         string   `json:"panel_url"`
	CAFile           string   `json:"ca_file"`
	StateDir         string   `json:"state_dir"`
	NftBinary        string   `json:"nft_binary"`
	NftTable         string   `json:"nft_table"`
	UplinkInterfaces []string `json:"uplink_interfaces"`
	ManagementCIDRs  []string `json:"management_cidrs"`
	HeartbeatSeconds int      `json:"heartbeat_seconds"`
	DetectMillis     int      `json:"detect_interval_ms"`
	ApprovalTimeoutS int      `json:"approval_timeout_seconds"`
	// XDPInterfaces enables the XDP early-drop filter on these interfaces. Empty = off.
	XDPInterfaces []string `json:"xdp_interfaces"`
	XDPMode       string   `json:"xdp_mode"`    // auto (default), native or generic
	XDPPinDir     string   `json:"xdp_pin_dir"` // where links are pinned so XDP survives an agent restart
}

// LoadConfig reads and validates a configuration file.
func LoadConfig(path string) (Config, error) {
	var c Config
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(bytesReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	c.applyDefaults()
	return c, c.Validate()
}

func (c *Config) applyDefaults() {
	if c.StateDir == "" {
		c.StateDir = "/var/lib/sentinel-shield"
	}
	if c.NftBinary == "" {
		c.NftBinary = "nft"
	}
	if c.NftTable == "" {
		c.NftTable = "sentinel_shield"
	}
	if c.HeartbeatSeconds == 0 {
		c.HeartbeatSeconds = 30
	}
	if c.DetectMillis == 0 {
		c.DetectMillis = 1000
	}
	if c.ApprovalTimeoutS == 0 {
		c.ApprovalTimeoutS = 900
	}
	if c.XDPMode == "" {
		c.XDPMode = "auto"
	}
	if c.XDPPinDir == "" {
		c.XDPPinDir = "/sys/fs/bpf/sentinel-shield"
	}
}

// Validate checks the configuration before the agent touches the firewall.
func (c Config) Validate() error {
	var errs []error
	if c.PanelURL == "" {
		errs = append(errs, errors.New("panel_url fehlt"))
	}
	if len(c.ManagementCIDRs) == 0 {
		errs = append(errs, errors.New("management_cidrs ist leer: ohne Management-Netz kann sich der Agent nicht vor versehentlicher Sperrung schützen"))
	}
	for _, s := range c.ManagementCIDRs {
		if _, err := netaddr.ParsePrefix(s); err != nil {
			errs = append(errs, fmt.Errorf("management_cidrs: %w", err))
		}
	}
	if c.HeartbeatSeconds < 5 || c.HeartbeatSeconds > 3600 {
		errs = append(errs, errors.New("heartbeat_seconds muss zwischen 5 und 3600 liegen"))
	}
	if c.DetectMillis < 200 || c.DetectMillis > 10000 {
		errs = append(errs, errors.New("detect_interval_ms muss zwischen 200 und 10000 liegen"))
	}
	switch c.XDPMode {
	case "", "auto", "native", "generic":
	default:
		errs = append(errs, errors.New("xdp_mode muss auto, native oder generic sein"))
	}
	if c.ApprovalTimeoutS < 60 {
		errs = append(errs, errors.New("approval_timeout_seconds muss >= 60 sein"))
	}
	return errors.Join(errs...)
}

// ManagementPrefixes returns the parsed management networks.
func (c Config) ManagementPrefixes() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range c.ManagementCIDRs {
		p, err := netaddr.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// DetectInterval returns the sampling interval.
func (c Config) DetectInterval() time.Duration {
	return time.Duration(c.DetectMillis) * time.Millisecond
}

// HeartbeatInterval returns the heartbeat interval.
func (c Config) HeartbeatInterval() time.Duration {
	return time.Duration(c.HeartbeatSeconds) * time.Second
}
