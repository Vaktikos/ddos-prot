// Package signer provides the ways the panel can sign policies: with a key file, with an
// external program (for an HSM through PKCS#11 tools or a cloud KMS CLI), or through
// HashiCorp Vault's Transit engine. All of them produce plain Ed25519 signatures, so agents
// verify them the same way and do not know which one is in use.
package signer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/vaktikos/ddos-prot/internal/identity"
)

// Signer signs messages and knows its public key.
type Signer interface {
	Sign(msg []byte) ([]byte, error)
	Public() ed25519.PublicKey
	// Describe names the backend for logs; it never contains secrets.
	Describe() string
}

// SelfTest signs a random message and verifies it against the public key, so a wrong key
// or a broken command is found at startup instead of at the first policy publication.
func SelfTest(s Signer) error {
	msg := make([]byte, 32)
	if _, err := rand.Read(msg); err != nil {
		return err
	}
	sig, err := s.Sign(msg)
	if err != nil {
		return fmt.Errorf("selbsttest: signieren: %w", err)
	}
	if !ed25519.Verify(s.Public(), msg, sig) {
		return errors.New("selbsttest: die Signatur passt nicht zum konfigurierten öffentlichen Schlüssel")
	}
	return nil
}

// --- file ---------------------------------------------------------------------------

type fileSigner struct {
	priv ed25519.PrivateKey
	path string
}

// NewFile loads the key file, creating it with mode 0600 on first start.
func NewFile(path string) (Signer, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		_, priv, err := identity.GenerateKey()
		if err != nil {
			return nil, err
		}
		if err := identity.SaveKey(path, priv); err != nil {
			return nil, fmt.Errorf("signaturschlüssel anlegen: %w", err)
		}
	}
	priv, err := identity.LoadKey(path)
	if err != nil {
		return nil, err
	}
	return &fileSigner{priv: priv, path: path}, nil
}

// FromKey wraps an existing private key (used by tests and tools).
func FromKey(priv ed25519.PrivateKey) Signer { return &fileSigner{priv: priv, path: "(speicher)"} }

func (f *fileSigner) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(f.priv, msg), nil }
func (f *fileSigner) Public() ed25519.PublicKey       { return f.priv.Public().(ed25519.PublicKey) }
func (f *fileSigner) Describe() string                { return "datei " + f.path }

// Seed exposes the file key's seed. Only the legacy MFA key derivation uses it.
func (f *fileSigner) Seed() []byte { return f.priv.Seed() }

// --- external command ---------------------------------------------------------------

type commandSigner struct {
	argv    []string
	pub     ed25519.PublicKey
	timeout time.Duration
}

// NewCommand signs by running argv with the message on stdin. The program must print the
// Ed25519 signature on stdout, either as 64 raw bytes or as base64. No shell is involved,
// so the argument list is never interpreted. pub is the matching public key.
func NewCommand(argv []string, pub ed25519.PublicKey, timeout time.Duration) (Signer, error) {
	if len(argv) == 0 || argv[0] == "" {
		return nil, errors.New("signer-befehl ist leer")
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("öffentlicher Schlüssel für den Signer-Befehl fehlt oder ist ungültig")
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &commandSigner{argv: argv, pub: pub, timeout: timeout}, nil
}

func (c *commandSigner) Public() ed25519.PublicKey { return c.pub }
func (c *commandSigner) Describe() string          { return "befehl " + c.argv[0] }

func (c *commandSigner) Sign(msg []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.argv[0], c.argv[1:]...)
	cmd.Stdin = bytes.NewReader(msg)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("signer-befehl: %w: %s", err, strings.TrimSpace(errb.String()))
	}
	raw := bytes.TrimSpace(out.Bytes())
	if len(raw) == ed25519.SignatureSize {
		return raw, nil
	}
	sig, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("signer-befehl lieferte keine 64-Byte-Signatur (roh oder base64)")
	}
	return sig, nil
}

// --- HashiCorp Vault Transit --------------------------------------------------------

type vaultSigner struct {
	addr, tokenFile, mount, key string
	version                     int
	pub                         ed25519.PublicKey
	hc                          *http.Client
}

// NewVault signs with a Transit key of type ed25519. The token is read from tokenFile on
// every request, so a renewed token is picked up without a restart. version 0 means latest.
func NewVault(addr, tokenFile, mount, key string, version int, hc *http.Client) (Signer, error) {
	if !strings.HasPrefix(addr, "https://") && !strings.HasPrefix(addr, "http://127.0.0.1") && !strings.HasPrefix(addr, "http://localhost") {
		return nil, errors.New("vault-adresse muss https verwenden (http nur für localhost)")
	}
	if mount == "" {
		mount = "transit"
	}
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	v := &vaultSigner{addr: strings.TrimRight(addr, "/"), tokenFile: tokenFile, mount: mount, key: key, version: version, hc: hc}
	if err := v.loadPublic(); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *vaultSigner) Public() ed25519.PublicKey { return v.pub }
func (v *vaultSigner) Describe() string          { return "vault " + v.mount + "/" + v.key }

func (v *vaultSigner) do(method, path string, in any, out any) error {
	tok, err := os.ReadFile(v.tokenFile)
	if err != nil {
		return fmt.Errorf("vault-token: %w", err)
	}
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, v.addr+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", strings.TrimSpace(string(tok)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vault antwortet %d", resp.StatusCode)
	}
	return json.Unmarshal(data, out)
}

func (v *vaultSigner) loadPublic() error {
	var r struct {
		Data struct {
			Type          string                    `json:"type"`
			LatestVersion int                       `json:"latest_version"`
			Keys          map[string]map[string]any `json:"keys"`
		} `json:"data"`
	}
	if err := v.do(http.MethodGet, "/v1/"+v.mount+"/keys/"+v.key, nil, &r); err != nil {
		return err
	}
	if r.Data.Type != "ed25519" {
		return fmt.Errorf("vault-schlüssel %q hat Typ %q, erwartet ed25519", v.key, r.Data.Type)
	}
	ver := v.version
	if ver == 0 {
		ver = r.Data.LatestVersion
	}
	entry, ok := r.Data.Keys[fmt.Sprint(ver)]
	if !ok {
		return fmt.Errorf("vault-schlüssel %q hat keine Version %d", v.key, ver)
	}
	pubB64, _ := entry["public_key"].(string)
	raw, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return errors.New("vault lieferte keinen gültigen öffentlichen Schlüssel")
	}
	v.pub, v.version = ed25519.PublicKey(raw), ver
	return nil
}

func (v *vaultSigner) Sign(msg []byte) ([]byte, error) {
	var r struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	in := map[string]any{"input": base64.StdEncoding.EncodeToString(msg), "key_version": v.version}
	if err := v.do(http.MethodPost, "/v1/"+v.mount+"/sign/"+v.key, in, &r); err != nil {
		return nil, err
	}
	parts := strings.Split(r.Data.Signature, ":")
	if len(parts) != 3 || parts[0] != "vault" {
		return nil, errors.New("unerwartetes Signaturformat von vault")
	}
	sig, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("vault lieferte keine 64-Byte-Signatur")
	}
	return sig, nil
}
