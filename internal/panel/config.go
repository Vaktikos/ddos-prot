// Package panel implements the control plane: the authenticated management API,
// the agent API, policy compilation and signing, metrics ingestion and alerting.
package panel

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vaktikos/ddos-prot/internal/identity"
	"github.com/vaktikos/ddos-prot/internal/signer"
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
	DownloadDir  string // agent binaries and SHA256SUMS served to the installer
	CookieSecure bool
	SessionHours int
	SeedEmail    string
	SeedPassword string

	// Signing backend: "file" (default), "command" or "vault".
	Signer          string
	SignerCommand   []string // argv, no shell
	SignerPublicKey string   // base64 Ed25519 public key for the command signer
	VaultAddr       string
	VaultTokenFile  string
	VaultMount      string
	VaultKey        string
	VaultKeyVersion int
	NextPublicKey   string // base64; announced to agents before a key rotation
	DataKeyFile     string // 32 random bytes for MFA secrets; independent of the signing key
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
		DownloadDir:  env("PANEL_DOWNLOAD_DIR", ""),
		CookieSecure: env("PANEL_COOKIE_SECURE", "true") != "false",
		SessionHours: envInt("PANEL_SESSION_HOURS", 12),
		SeedEmail:    env("PANEL_ADMIN_EMAIL", ""),

		Signer:          env("PANEL_SIGNER", "file"),
		SignerPublicKey: env("PANEL_SIGNER_PUBLIC_KEY", ""),
		VaultAddr:       env("PANEL_VAULT_ADDR", ""),
		VaultTokenFile:  env("PANEL_VAULT_TOKEN_FILE", ""),
		VaultMount:      env("PANEL_VAULT_MOUNT", "transit"),
		VaultKey:        env("PANEL_VAULT_KEY", ""),
		VaultKeyVersion: envInt("PANEL_VAULT_KEY_VERSION", 0),
		NextPublicKey:   env("PANEL_NEXT_SIGNING_PUBLIC_KEY", ""),
		DataKeyFile:     env("PANEL_DATA_KEY_FILE", ""),
	}
	if raw := env("PANEL_SIGNER_COMMAND", ""); raw != "" {
		if err := json.Unmarshal([]byte(raw), &c.SignerCommand); err != nil {
			return c, fmt.Errorf("PANEL_SIGNER_COMMAND muss ein JSON-Array sein, z. B. [\"/usr/local/bin/sign\"]: %w", err)
		}
	}
	if p := env("PANEL_ADMIN_PASSWORD_FILE", ""); p != "" {
		raw, err := os.ReadFile(p)
		if err != nil {
			return c, fmt.Errorf("PANEL_ADMIN_PASSWORD_FILE: %w", err)
		}
		c.SeedPassword = strings.TrimSpace(string(raw))
	}
	var errs []error
	switch c.Signer {
	case "file":
	case "command":
		if len(c.SignerCommand) == 0 || c.SignerPublicKey == "" {
			errs = append(errs, errors.New("PANEL_SIGNER=command braucht PANEL_SIGNER_COMMAND und PANEL_SIGNER_PUBLIC_KEY"))
		}
	case "vault":
		if c.VaultAddr == "" || c.VaultTokenFile == "" || c.VaultKey == "" {
			errs = append(errs, errors.New("PANEL_SIGNER=vault braucht PANEL_VAULT_ADDR, PANEL_VAULT_TOKEN_FILE und PANEL_VAULT_KEY"))
		}
	default:
		errs = append(errs, errors.New("PANEL_SIGNER muss file, command oder vault sein"))
	}
	if c.Signer != "file" && c.DataKeyFile == "" {
		c.DataKeyFile = filepath.Join(filepath.Dir(c.SigningKey), "data.key")
	}
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

// DecodePublicKey parses a base64 Ed25519 public key.
func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("öffentlicher Ed25519-Schlüssel muss base64 mit 32 Byte sein")
	}
	return ed25519.PublicKey(raw), nil
}

// LoadOrCreateDataKey returns 32 random bytes used to encrypt stored MFA secrets. It is
// created on first start with mode 0600 and is independent of the signing key, so an HSM
// that never reveals its key still leaves the panel able to protect its own data.
func LoadOrCreateDataKey(path string) ([]byte, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path+".tmp", []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0o600); err != nil {
			return nil, err
		}
		if err := os.Rename(path+".tmp", path); err != nil {
			return nil, err
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: Berechtigungen %s sind zu offen (erwartet 0600)", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("%s: ungültiger Datenschlüssel", path)
	}
	return key, nil
}

// BuildSigner creates the configured signing backend and checks it with a test signature.
func BuildSigner(c Config) (signer.Signer, error) {
	var s signer.Signer
	var err error
	switch c.Signer {
	case "command":
		var pub ed25519.PublicKey
		if pub, err = DecodePublicKey(c.SignerPublicKey); err != nil {
			return nil, err
		}
		s, err = signer.NewCommand(c.SignerCommand, pub, 0)
	case "vault":
		s, err = signer.NewVault(c.VaultAddr, c.VaultTokenFile, c.VaultMount, c.VaultKey, c.VaultKeyVersion, nil)
	default:
		s, err = signer.NewFile(c.SigningKey)
	}
	if err != nil {
		return nil, err
	}
	if err := signer.SelfTest(s); err != nil {
		return nil, err
	}
	return s, nil
}
