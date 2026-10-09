package identity

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func signedRequest(t *testing.T, now time.Time, body []byte) (*http.Request, []byte) {
	t.Helper()
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://panel.example/agent/v1/heartbeat", bytes.NewReader(body))
	if err := Sign(req, "node-1", priv, body, now); err != nil {
		t.Fatal(err)
	}
	return req, pub
}

func TestSignVerifyRoundTrip(t *testing.T) {
	now := time.Now()
	body := []byte(`{"cpu":12.5}`)
	req, pub := signedRequest(t, now, body)
	v, err := Verify(req, body, pub, now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.NodeID != "node-1" {
		t.Fatalf("NodeID = %q", v.NodeID)
	}
}

func TestVerifyRejectsTamperedBodyAndWrongKey(t *testing.T) {
	now := time.Now()
	req, pub := signedRequest(t, now, []byte(`{"a":1}`))
	if _, err := Verify(req, []byte(`{"a":2}`), pub, now); err == nil {
		t.Fatal("verändertes Body wurde akzeptiert")
	}
	other, _, _ := GenerateKey()
	if _, err := Verify(req, []byte(`{"a":1}`), other, now); err == nil {
		t.Fatal("Signatur mit fremdem Schlüssel wurde akzeptiert")
	}
}

func TestVerifyRejectsStaleTimestamp(t *testing.T) {
	now := time.Now()
	body := []byte("{}")
	req, pub := signedRequest(t, now.Add(-5*time.Minute), body)
	if _, err := Verify(req, body, pub, now); err == nil {
		t.Fatal("veralteter Zeitstempel wurde akzeptiert")
	}
}

func TestVerifyRejectsMissingHeaders(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://panel.example/agent/v1/policy", nil)
	pub, _, _ := GenerateKey()
	if _, err := Verify(req, nil, pub, time.Now()); err == nil {
		t.Fatal("fehlende Header wurden akzeptiert")
	}
}

func TestNonceStoreDetectsReplay(t *testing.T) {
	s := NewMemoryNonceStore()
	exp := time.Now().Add(time.Minute)
	ok, _ := s.Record("n", "abcdefghijklmnop", exp)
	again, _ := s.Record("n", "abcdefghijklmnop", exp)
	if !ok || again {
		t.Fatalf("Replay nicht erkannt: first=%v second=%v", ok, again)
	}
	other, _ := s.Record("m", "abcdefghijklmnop", exp)
	if !other {
		t.Fatal("Nonce ist pro Node getrennt zu betrachten")
	}
}

func TestKeyFileRoundTripAndPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.key")
	_, priv, _ := GenerateKey()
	if err := SaveKey(path, priv); err != nil {
		t.Fatal(err)
	}
	got, err := LoadKey(path)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if !bytes.Equal(got, priv) {
		t.Fatal("Schlüssel stimmt nach dem Laden nicht überein")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(path); err == nil {
		t.Fatal("zu offene Schlüsseldatei wurde akzeptiert")
	}
}
