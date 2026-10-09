package agent

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vaktikos/ddos-prot/internal/identity"
	"github.com/vaktikos/ddos-prot/internal/policy"
)

// NodeFile is the enrollment result stored on the node.
type NodeFile struct {
	NodeID         string `json:"node_id"`
	PanelPublicKey string `json:"panel_public_key"` // first trusted key; kept for older agents
	// PanelPublicKeys is the full trusted set. Empty in files written by older versions.
	PanelPublicKeys []string `json:"panel_public_keys,omitempty"`
	KeysetIssuedAt  int64    `json:"keyset_issued_at,omitempty"`
}

// Paths of files in the state directory.
const (
	nodeFileName     = "node.json"
	identityFileName = "identity.key"
	policyCacheName  = "policy-cache.json"
	nextIdentityName = "identity.key.next"
)

// Store persists identity and the last verified policy so that the agent can
// start and protect without the panel.
type Store struct{ Dir string }

// LoadNode returns the enrollment data, or an error if the node is not enrolled.
func (s Store) LoadNode() (NodeFile, ed25519.PrivateKey, []ed25519.PublicKey, error) {
	var nf NodeFile
	raw, err := os.ReadFile(filepath.Join(s.Dir, nodeFileName))
	if err != nil {
		return nf, nil, nil, fmt.Errorf("node nicht eingeschrieben (%w): sentinel-agent enroll ausführen", err)
	}
	if err := json.Unmarshal(raw, &nf); err != nil {
		return nf, nil, nil, err
	}
	encoded := nf.PanelPublicKeys
	if len(encoded) == 0 {
		encoded = []string{nf.PanelPublicKey} // file written before key sets existed
	}
	var pubs []ed25519.PublicKey
	for _, e := range encoded {
		raw, err := base64.StdEncoding.DecodeString(e)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nf, nil, nil, errors.New("panel_public_key ungültig")
		}
		pubs = append(pubs, ed25519.PublicKey(raw))
	}
	priv, err := identity.LoadKey(filepath.Join(s.Dir, identityFileName))
	if err != nil {
		return nf, nil, nil, err
	}
	return nf, priv, pubs, nil
}

// SaveNode writes the enrollment data atomically.
func (s Store) SaveNode(nf NodeFile) error {
	raw, err := json.MarshalIndent(nf, "", "  ")
	if err != nil {
		return err
	}
	return s.writeAtomic(nodeFileName, raw, 0o600)
}

// SaveEnvelope caches the last envelope that passed signature verification.
func (s Store) SaveEnvelope(env policy.Envelope) error {
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return s.writeAtomic(policyCacheName, raw, 0o600)
}

// LoadEnvelope returns the cached envelope, or nil if none exists.
func (s Store) LoadEnvelope() (*policy.Envelope, error) {
	raw, err := os.ReadFile(filepath.Join(s.Dir, policyCacheName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var env policy.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("policy-cache beschädigt: %w", err)
	}
	return &env, nil
}

func (s Store) writeAtomic(name string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	final := filepath.Join(s.Dir, name)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}
