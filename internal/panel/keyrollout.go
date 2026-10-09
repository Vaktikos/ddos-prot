package panel

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/vaktikos/ddos-prot/internal/policy"
)

// announceKeys signs the statement that tells agents which panel keys to trust: the active
// key and, during a rotation, the next one. It is signed by the active key, which every
// agent already trusts. IssuedAt grows with each start, so an old statement cannot be replayed.
func (a *App) announceKeys() error {
	keys := []string{base64.StdEncoding.EncodeToString(a.pub)}
	if len(a.nextPub) == ed25519.PublicKeySize && !a.nextPub.Equal(a.pub) {
		keys = append(keys, base64.StdEncoding.EncodeToString(a.nextPub))
	}
	sks, err := policy.SignKeySet(a.sg, a.pub, policy.KeySet{Keys: keys, IssuedAt: time.Now().UnixMilli()})
	if err != nil {
		return err
	}
	a.keyset = sks
	return nil
}

// legacyMFAKey is how MFA secrets were encrypted before the separate data key existed.
func legacyMFAKey(priv ed25519.PrivateKey) []byte { return legacyMFAKeyFromSeed(priv.Seed()) }

func legacyMFAKeyFromSeed(seed []byte) []byte {
	h := sha256.New()
	h.Write([]byte("sentinel-shield mfa v1"))
	h.Write(seed)
	return h.Sum(nil)
}

type signingNode struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Status        string   `json:"status"`
	TrustedKeyIDs []string `json:"trusted_key_ids"`
	KnowsNext     bool     `json:"knows_next_key"`
}

// signingStatus tells an administrator where a key rotation stands. It is safe to switch
// the panel to the next key only when every enrolled node reports that it trusts it.
func (a *App) signingStatus(w http.ResponseWriter, r *http.Request, _ Actor) {
	rows, err := a.db.Query(r.Context(), `SELECT id::text, name, status, trusted_key_ids FROM nodes
		WHERE public_key IS NOT NULL AND status <> 'revoked' ORDER BY name`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "abfrage fehlgeschlagen")
		return
	}
	defer rows.Close()
	next := ""
	if len(a.nextPub) == ed25519.PublicKeySize {
		next = policy.KeyID(a.nextPub)
	}
	nodes := []signingNode{}
	ready := next != ""
	for rows.Next() {
		var n signingNode
		if err := rows.Scan(&n.ID, &n.Name, &n.Status, &n.TrustedKeyIDs); err != nil {
			writeErr(w, http.StatusInternalServerError, "lesefehler")
			return
		}
		for _, id := range n.TrustedKeyIDs {
			if id == next {
				n.KnowsNext = true
			}
		}
		if !n.KnowsNext {
			ready = false
		}
		nodes = append(nodes, n)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"backend":         a.sg.Describe(),
		"active_key_id":   policy.KeyID(a.pub),
		"next_key_id":     next,
		"nodes":           nodes,
		"ready_to_switch": ready,
	})
}
