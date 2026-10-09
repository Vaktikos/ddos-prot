package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileSignerCreatesKeyAndPassesSelfTest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "signing.key")
	s, err := NewFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := SelfTest(s); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("Schlüsseldatei hat Rechte %v", info.Mode().Perm())
	}
	again, _ := NewFile(path)
	if !again.Public().Equal(s.Public()) {
		t.Fatal("der zweite Start muss denselben Schlüssel laden")
	}
}

// Uses the real openssl binary as the "HSM": the key lives in a file the panel never reads.
func TestCommandSignerWithOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl nicht installiert")
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k.pem")
	if out, err := exec.Command("openssl", "genpkey", "-algorithm", "ed25519", "-out", keyPath).CombinedOutput(); err != nil {
		t.Skipf("openssl ohne ed25519: %v %s", err, out)
	}
	der, err := exec.Command("openssl", "pkey", "-in", keyPath, "-pubout", "-outform", "DER").Output()
	if err != nil || len(der) < ed25519.PublicKeySize {
		t.Fatalf("öffentlicher Schlüssel: %v", err)
	}
	pub := ed25519.PublicKey(der[len(der)-ed25519.PublicKeySize:])
	script := filepath.Join(dir, "sign.sh")
	body := "#!/bin/sh\nset -e\nt=$(mktemp)\ncat > \"$t\"\nopenssl pkeyutl -sign -rawin -inkey '" + keyPath + "' -in \"$t\" | base64 -w0\nrm -f \"$t\"\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := NewCommand([]string{script}, pub, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := SelfTest(s); err != nil {
		t.Fatalf("Selbsttest mit openssl: %v", err)
	}

	// A signer whose public key does not match must fail the self-test.
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	bad, _ := NewCommand([]string{script}, wrong, 10*time.Second)
	if err := SelfTest(bad); err == nil {
		t.Fatal("falscher öffentlicher Schlüssel muss im Selbsttest auffallen")
	}
}

func TestCommandSignerRejectsBrokenOutputAndFailure(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	garbage, _ := NewCommand([]string{"/bin/sh", "-c", "echo not-a-signature"}, pub, 5*time.Second)
	if _, err := garbage.Sign([]byte("x")); err == nil {
		t.Fatal("Müll als Signatur muss abgelehnt werden")
	}
	failing, _ := NewCommand([]string{"/bin/false"}, pub, 5*time.Second)
	if _, err := failing.Sign([]byte("x")); err == nil {
		t.Fatal("Fehlerexit muss als Fehler gelten")
	}
	slow, _ := NewCommand([]string{"/bin/sleep", "5"}, pub, 200*time.Millisecond)
	start := time.Now()
	if _, err := slow.Sign([]byte("x")); err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("Zeitlimit greift nicht (%v)", time.Since(start))
	}
	if _, err := NewCommand(nil, pub, 0); err == nil {
		t.Fatal("leerer Befehl muss abgelehnt werden")
	}
}

// fakeVault implements the two Transit endpoints used by the signer.
func fakeVault(t *testing.T, priv ed25519.PrivateKey, keyType string) *httptest.Server {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "s.testtoken" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/ss":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"type": keyType, "latest_version": 2,
				"keys": map[string]any{"2": map[string]any{"public_key": base64.StdEncoding.EncodeToString(pub)}},
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/transit/sign/ss":
			var in struct {
				Input string `json:"input"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			msg, _ := base64.StdEncoding.DecodeString(in.Input)
			sig := ed25519.Sign(priv, msg)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"signature": "vault:v2:" + base64.StdEncoding.EncodeToString(sig)}})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestVaultSigner(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := fakeVault(t, priv, "ed25519")
	defer srv.Close()
	tok := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(tok, []byte("s.testtoken\n"), 0o600)

	s, err := NewVault(srv.URL, tok, "", "ss", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Public().Equal(priv.Public()) {
		t.Fatal("öffentlicher Schlüssel muss aus Vault gelesen werden")
	}
	if err := SelfTest(s); err != nil {
		t.Fatal(err)
	}

	badTok := filepath.Join(t.TempDir(), "bad")
	_ = os.WriteFile(badTok, []byte("wrong"), 0o600)
	if _, err := NewVault(srv.URL, badTok, "", "ss", 0, nil); err == nil {
		t.Fatal("falsches Token muss scheitern")
	}
	wrongType := fakeVault(t, priv, "rsa-2048")
	defer wrongType.Close()
	if _, err := NewVault(wrongType.URL, tok, "", "ss", 0, nil); err == nil || !strings.Contains(err.Error(), "ed25519") {
		t.Fatalf("falscher Schlüsseltyp muss abgelehnt werden: %v", err)
	}
	if _, err := NewVault("http://vault.example.com", tok, "", "ss", 0, nil); err == nil {
		t.Fatal("unverschlüsseltes http außerhalb von localhost darf nicht erlaubt sein")
	}
}
