package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func b64(k ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(k) }

func TestKeySetRolloverChain(t *testing.T) {
	oldPub, oldPriv := newKey(t)
	newPub, newPriv := newKey(t)

	// Step 1: the old key announces the new one.
	announce, err := SignKeySet(FromPrivateKey(oldPriv), oldPub, KeySet{Keys: []string{b64(oldPub), b64(newPub)}, IssuedAt: 100})
	if err != nil {
		t.Fatal(err)
	}
	_, trusted, err := VerifyKeySet([]ed25519.PublicKey{oldPub}, announce, 0)
	if err != nil || len(trusted) != 2 {
		t.Fatalf("Ankündigung: %v (%d Schlüssel)", err, len(trusted))
	}
	// Step 2: the new key retires the old one.
	retire, _ := SignKeySet(FromPrivateKey(newPriv), newPub, KeySet{Keys: []string{b64(newPub)}, IssuedAt: 200})
	_, only, err := VerifyKeySet(trusted, retire, 100)
	if err != nil || len(only) != 1 || !only[0].Equal(newPub) {
		t.Fatalf("Ausmusterung: %v", err)
	}
}

func TestKeySetRejectsUntrustedStaleAndMalformed(t *testing.T) {
	pub, priv := newKey(t)
	otherPub, otherPriv := newKey(t)

	rogue, _ := SignKeySet(FromPrivateKey(otherPriv), otherPub, KeySet{Keys: []string{b64(otherPub)}, IssuedAt: 100})
	if _, _, err := VerifyKeySet([]ed25519.PublicKey{pub}, rogue, 0); err == nil {
		t.Fatal("von einem unbekannten Schlüssel signierte Menge wurde akzeptiert")
	}
	good, _ := SignKeySet(FromPrivateKey(priv), pub, KeySet{Keys: []string{b64(pub)}, IssuedAt: 100})
	if _, _, err := VerifyKeySet([]ed25519.PublicKey{pub}, good, 100); err == nil {
		t.Fatal("nicht neuere Menge (Replay) wurde akzeptiert")
	}
	tampered := good
	tampered.Body = `{"keys":["` + b64(otherPub) + `"],"issued_at":999}`
	if _, _, err := VerifyKeySet([]ed25519.PublicKey{pub}, tampered, 0); err == nil {
		t.Fatal("manipulierter Body wurde akzeptiert")
	}
	empty, _ := SignKeySet(FromPrivateKey(priv), pub, KeySet{Keys: []string{"AAAA"}, IssuedAt: 5})
	if _, _, err := VerifyKeySet([]ed25519.PublicKey{pub}, empty, 0); err == nil {
		t.Fatal("ungültiger Schlüssel in der Menge wurde akzeptiert")
	}
	if _, err := SignKeySet(FromPrivateKey(priv), pub, KeySet{}); err == nil {
		t.Fatal("leere Menge darf nicht signiert werden")
	}
}

func TestOpenAnyAcceptsAnyTrustedKey(t *testing.T) {
	pubA, _ := newKey(t)
	pubB, privB := newKey(t)
	env, err := Sign(privB, basePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if env.KeyID != KeyID(pubB) {
		t.Fatalf("KeyID = %s", env.KeyID)
	}
	if _, err := OpenAny([]ed25519.PublicKey{pubA, pubB}, env, nil); err != nil {
		t.Fatalf("vertrauter zweiter Schlüssel: %v", err)
	}
	if _, err := OpenAny([]ed25519.PublicKey{pubA}, env, nil); err == nil {
		t.Fatal("ohne passenden Schlüssel muss abgelehnt werden")
	}
}
