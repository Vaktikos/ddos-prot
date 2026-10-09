package policy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Signer signs messages without exposing a private key to this process. Implementations
// can sit in front of a file, an external command, an HSM or a KMS.
type Signer interface {
	Sign(msg []byte) ([]byte, error)
}

type privSigner struct{ k ed25519.PrivateKey }

func (p privSigner) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(p.k, msg), nil }

// FromPrivateKey wraps an in-memory key as a Signer.
func FromPrivateKey(k ed25519.PrivateKey) Signer { return privSigner{k} }

// KeyID is a short, stable identifier of a public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// KeySet is the list of panel public keys that agents may trust. IssuedAt only increases,
// so an old statement cannot be replayed to bring back a retired key.
type KeySet struct {
	Keys     []string `json:"keys"` // base64 Ed25519 public keys, active key first
	IssuedAt int64    `json:"issued_at"`
}

// SignedKeySet is a KeySet with the signature of a key the receiver already trusts.
type SignedKeySet struct {
	Body      string `json:"body"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// SignKeySet signs a key set with the signer behind signerPub.
func SignKeySet(s Signer, signerPub ed25519.PublicKey, ks KeySet) (SignedKeySet, error) {
	if len(ks.Keys) == 0 {
		return SignedKeySet{}, errors.New("schlüsselmenge ist leer")
	}
	body, err := json.Marshal(ks)
	if err != nil {
		return SignedKeySet{}, err
	}
	sig, err := s.Sign(body)
	if err != nil {
		return SignedKeySet{}, err
	}
	return SignedKeySet{Body: string(body), KeyID: KeyID(signerPub), Signature: base64.StdEncoding.EncodeToString(sig)}, nil
}

// VerifyKeySet checks the signature against the currently trusted keys and requires that
// the statement is newer than lastIssuedAt. It returns the parsed public keys.
func VerifyKeySet(trusted []ed25519.PublicKey, sks SignedKeySet, lastIssuedAt int64) (KeySet, []ed25519.PublicKey, error) {
	sig, err := base64.StdEncoding.DecodeString(sks.Signature)
	if err != nil {
		return KeySet{}, nil, fmt.Errorf("signatur nicht dekodierbar: %w", err)
	}
	ok := false
	for _, k := range trusted {
		if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, []byte(sks.Body), sig) {
			ok = true
			break
		}
	}
	if !ok {
		return KeySet{}, nil, errors.New("schlüsselmenge nicht von einem vertrauten Schlüssel signiert")
	}
	var ks KeySet
	dec := json.NewDecoder(strings.NewReader(sks.Body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ks); err != nil {
		return KeySet{}, nil, fmt.Errorf("schlüsselmenge nicht lesbar: %w", err)
	}
	if ks.IssuedAt <= lastIssuedAt {
		return KeySet{}, nil, errors.New("schlüsselmenge ist nicht neuer als die bekannte")
	}
	if len(ks.Keys) == 0 || len(ks.Keys) > 4 {
		return KeySet{}, nil, errors.New("schlüsselmenge muss 1 bis 4 Schlüssel enthalten")
	}
	var pubs []ed25519.PublicKey
	for _, k := range ks.Keys {
		raw, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return KeySet{}, nil, errors.New("ungültiger Schlüssel in der Menge")
		}
		pubs = append(pubs, ed25519.PublicKey(raw))
	}
	return ks, pubs, nil
}
