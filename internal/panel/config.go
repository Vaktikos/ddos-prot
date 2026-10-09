// Package panel implements the control plane: the authenticated management API,
// the agent API, policy compilation and signing, metrics ingestion and alerting.
package panel

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/vaktikos/ddos-prot/internal/identity"
)

// Config is read from environment variables (see deploy/.env.example).
type Config struct {
	Listen       string
	PublicURL    string
	DatabaseURL  string
	TLSCert      string
	TLSKey       string
	SigningKey   string
	WebDir       string
	CookieSecure bool
	SessionHours int
	SeedEmail    string
	SeedPassword string
}

// LoadConfig reads and validates the environment.
func LoadConfig() (Config, error) {
	c := Config{
		Listen:       env("PANEL_LISTEN", "127.0.0.1:8080"),
		PublicURL:    env("PANEL_PUBLIC_URL", ""),
		DatabaseURL:  os.Getenv("PANEL_DATABASE_URL"),
		TLSCert:      env("PANEL_TLS_CERT", ""),
		TLSKey:       env("PANEL_TLS_KEY", ""),
		SigningKey:   env("PANEL_SIGNING_KEY_FILE", "/var/lib/sentinel-panel/signing.key"),
		WebDir:       env("PANEL_WEB_DIR", ""),
		CookieSecure: env("PANEL_COOKIE_SECURE", "true") != "false",
		SessionHours: envInt("PANEL_SESSION_HOURS", 12),
		SeedEmail:    env("PANEL_ADMIN_EMAIL", ""),
	}
	if p := env("PANEL_ADMIN_PASSWORD_FILE", ""); p != "" {
		raw, err := os.ReadFile(p)
		if err != nil {
			return c, fmt.Errorf("PANEL_ADMIN_PASSWORD_FILE: %w", err)
		}
		c.SeedPassword = strings.TrimSpace(string(raw))
	}
	var errs []error
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("PANEL_DATABASE_URL fehlt"))
	}
	if !strings.HasPrefix(c.PublicURL, "https://") && !isLocalHTTP(c.PublicURL) {
		errs = append(errs, errors.New("PANEL_PUBLIC_URL muss https verwenden (http nur für localhost)"))
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		errs = append(errs, errors.New("PANEL_TLS_CERT und PANEL_TLS_KEY müssen gemeinsam gesetzt werden"))
	}
	if !c.CookieSecure && strings.HasPrefix(c.PublicURL, "https://") {
		errs = append(errs, errors.New("PANEL_COOKIE_SECURE=false ist bei https-Betrieb nicht zulässig"))
	}
	if c.SessionHours < 1 || c.SessionHours > 24 {
		errs = append(errs, errors.New("PANEL_SESSION_HOURS muss zwischen 1 und 24 liegen"))
	}
	return c, errors.Join(errs...)
}

func isLocalHTTP(u string) bool {
	return strings.HasPrefix(u, "http://127.0.0.1") || strings.HasPrefix(u, "http://localhost")
}

// LoadOrCreateSigningKey returns the panel's Ed25519 key used to sign policies.
// It is created on first start with mode 0600 and never leaves the panel.
func LoadOrCreateSigningKey(path string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		_, priv, err := identity.GenerateKey()
		if err != nil {
			return nil, nil, err
		}
		if err := identity.SaveKey(path, priv); err != nil {
			return nil, nil, fmt.Errorf("signaturschlüssel anlegen: %w", err)
		}
	}
	priv, err := identity.LoadKey(path)
	if err != nil {
		return nil, nil, err
	}
	return priv.Public().(ed25519.PublicKey), priv, nil
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
