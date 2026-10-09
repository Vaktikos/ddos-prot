// Package identity provides the cryptographic identity of an agent: an Ed25519
// key pair created on the node, and request signatures that bind method, path,
// timestamp, nonce and body hash. Replays are rejected by the panel's nonce store.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Header names used by signed agent requests.
const (
	HeaderNode      = "X-SS-Node"
	HeaderTimestamp = "X-SS-Timestamp"
	HeaderNonce     = "X-SS-Nonce"
	HeaderSignature = "X-SS-Signature"
)

// MaxClockSkew bounds how far a request timestamp may differ from the panel clock.
const MaxClockSkew = 60 * time.Second

// GenerateKey creates a new Ed25519 key pair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// SaveKey writes a private key with mode 0600 in a directory that only root can enter.
func SaveKey(path string, priv ed25519.PrivateKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	enc := base64.StdEncoding.EncodeToString(priv)
	if err := os.WriteFile(tmp, []byte(enc+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadKey reads a private key written by SaveKey. It refuses files readable by others.
func LoadKey(path string) (ed25519.PrivateKey, error) {
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
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s: falsche Schlüssellänge", path)
	}
	return ed25519.PrivateKey(b), nil
}

// Fingerprint returns a short, human-comparable identifier of a public key.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// canonical builds the string that is signed. Every field is covered.
func canonical(method, path, ts, nonce string, body []byte) string {
	sum := sha256.Sum256(body)
	return strings.Join([]string{"SS1", strings.ToUpper(method), path, ts, nonce, hex.EncodeToString(sum[:])}, "\n")
}

// Sign adds the identity headers to a request. body must be the exact bytes sent.
func Sign(req *http.Request, nodeID string, priv ed25519.PrivateKey, body []byte, now time.Time) error {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}
	ts := strconv.FormatInt(now.Unix(), 10)
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	sig := ed25519.Sign(priv, []byte(canonical(req.Method, req.URL.Path, ts, nonce, body)))
	req.Header.Set(HeaderNode, nodeID)
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(sig))
	return nil
}

// Verified describes an authenticated request.
type Verified struct {
	NodeID string
	Nonce  string
	Expiry time.Time
}

// Verify checks the identity headers against the node's registered public key.
// It does not check replay; the caller must record the nonce via NonceStore.
func Verify(req *http.Request, body []byte, pub ed25519.PublicKey, now time.Time) (Verified, error) {
	var v Verified
	v.NodeID = req.Header.Get(HeaderNode)
	ts := req.Header.Get(HeaderTimestamp)
	v.Nonce = req.Header.Get(HeaderNonce)
	sigB64 := req.Header.Get(HeaderSignature)
	if v.NodeID == "" || ts == "" || v.Nonce == "" || sigB64 == "" {
		return v, errors.New("identitätsheader fehlen")
	}
	if len(v.Nonce) < 16 || len(v.Nonce) > 64 {
		return v, errors.New("nonce hat ungültige Länge")
	}
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return v, errors.New("zeitstempel ungültig")
	}
	sent := time.Unix(unix, 0)
	if d := now.Sub(sent); d > MaxClockSkew || d < -MaxClockSkew {
		return v, fmt.Errorf("zeitstempel außerhalb von %s", MaxClockSkew)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return v, errors.New("signatur ungültig kodiert")
	}
	if len(pub) != ed25519.PublicKeySize {
		return v, errors.New("öffentlicher Schlüssel ungültig")
	}
	if !ed25519.Verify(pub, []byte(canonical(req.Method, req.URL.Path, ts, v.Nonce, body)), sig) {
		return v, errors.New("signatur stimmt nicht")
	}
	v.Expiry = sent.Add(MaxClockSkew * 2)
	return v, nil
}

// NonceStore records nonces so that a captured request cannot be replayed.
// Implementations must be atomic: Record returns false if the nonce was seen.
type NonceStore interface {
	Record(nodeID, nonce string, expires time.Time) (bool, error)
}

// MemoryNonceStore is for tests and single-process development only.
type MemoryNonceStore struct {
	seen map[string]time.Time
}

// NewMemoryNonceStore creates an in-memory store.
func NewMemoryNonceStore() *MemoryNonceStore {
	return &MemoryNonceStore{seen: map[string]time.Time{}}
}

// Record implements NonceStore.
func (m *MemoryNonceStore) Record(nodeID, nonce string, expires time.Time) (bool, error) {
	now := time.Now()
	for k, exp := range m.seen {
		if now.After(exp) {
			delete(m.seen, k)
		}
	}
	key := nodeID + "/" + nonce
	if _, dup := m.seen[key]; dup {
		return false, nil
	}
	m.seen[key] = expires
	return true, nil
}
