package panel

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vaktikos/ddos-prot/internal/store"
)

// RFC 6238 Appendix B: secret "12345678901234567890", T=59 -> 8 digits 94287082, 6 digits 287082.
func TestTOTPRFC6238Vector(t *testing.T) {
	secret := []byte("12345678901234567890")
	if got := totpAt(secret, 59/totpStep); got != "287082" {
		t.Fatalf("totpAt(59) = %s, want 287082", got)
	}
}

func TestTOTPRejectsReplayAndOutOfWindow(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1_000_000_000, 0)
	cur := now.Unix() / totpStep
	code := totpAt(secret, cur)
	step := verifyTOTP(secret, code, now, 0)
	if step != cur {
		t.Fatalf("gültiger Code abgelehnt (step=%d)", step)
	}
	if verifyTOTP(secret, code, now, step) >= 0 {
		t.Fatal("bereits verwendeter Code darf nicht erneut gelten")
	}
	if verifyTOTP(secret, totpAt(secret, cur+5), now, 0) >= 0 {
		t.Fatal("Code außerhalb des Toleranzfensters darf nicht gelten")
	}
	if verifyTOTP(secret, "12ab56", now, 0) >= 0 {
		t.Fatal("nicht-numerischer Code darf nicht gelten")
	}
}

func TestSecretSealRoundTrip(t *testing.T) {
	_, priv, _ := LoadOrCreateSigningKey(filepath.Join(t.TempDir(), "k"))
	a := &App{priv: priv}
	enc, err := a.sealSecret([]byte("0123456789abcdef0123"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(enc, "0123456789") {
		t.Fatal("Klartext darf nicht im Chiffrat stehen")
	}
	dec, err := a.openSecret(enc)
	if err != nil || string(dec) != "0123456789abcdef0123" {
		t.Fatalf("Entschlüsselung fehlgeschlagen: %v", err)
	}
}

// TestMFALoginFlow runs the second factor end to end against PostgreSQL.
func TestMFALoginFlow(t *testing.T) {
	dsn := envDSN(t)
	ctx := context.Background()
	pool, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	resetSchema(t, pool)
	if err := store.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	base := "http://" + ln.Addr().String()
	cfg := Config{PublicURL: base, DatabaseURL: dsn, SigningKey: filepath.Join(t.TempDir(), "k"),
		SessionHours: 12, SeedEmail: "admin@example.test", SeedPassword: "correct horse battery"}
	pub, priv, _ := LoadOrCreateSigningKey(cfg.SigningKey)
	app, _ := New(cfg, pool, slog.New(slog.NewTextHandler(io.Discard, nil)), pub, priv)
	if err := app.EnsureSeedAdmin(ctx); err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: app.Handler()}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	admin := newAPIClient(t, base)
	admin.login(cfg.SeedEmail, cfg.SeedPassword)
	code, body := admin.call(http.MethodPost, "/api/v1/auth/mfa/enroll", nil)
	mustOK(t, "mfa einrichten", code, body, http.StatusOK)
	var enroll struct {
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal(body, &enroll)
	secret, err := b32.DecodeString(enroll.Secret)
	if err != nil {
		t.Fatal(err)
	}
	code, body = admin.call(http.MethodPost, "/api/v1/auth/mfa/enable", map[string]string{"code": totpAt(secret, time.Now().Unix()/totpStep)})
	mustOK(t, "mfa aktivieren", code, body, http.StatusOK)

	// Password alone now yields a second-factor request, not a session.
	code, body = admin.call(http.MethodPost, "/api/v1/auth/login", map[string]string{"email": cfg.SeedEmail, "password": cfg.SeedPassword})
	mustOK(t, "passwort allein", code, body, http.StatusOK)
	if !strings.Contains(string(body), `"mfa_required":true`) {
		t.Fatalf("zweiter Faktor wurde nicht verlangt: %s", body)
	}
	// Wrong code is refused.
	code, body = admin.call(http.MethodPost, "/api/v1/auth/login", map[string]string{"email": cfg.SeedEmail, "password": cfg.SeedPassword, "otp": "000000"})
	mustOK(t, "falscher code", code, body, http.StatusUnauthorized)

	// Correct code of the current step signs in; the same code cannot be reused.
	// The enable code consumed the current step; a login must use a later one.
	good := totpAt(secret, time.Now().Unix()/totpStep+1)
	code, body = admin.call(http.MethodPost, "/api/v1/auth/login", map[string]string{"email": cfg.SeedEmail, "password": cfg.SeedPassword, "otp": good})
	mustOK(t, "richtiger code", code, body, http.StatusOK)
	if !strings.Contains(string(body), "csrf_token") {
		t.Fatalf("keine Sitzung nach gültigem Code: %s", body)
	}
	code, body = admin.call(http.MethodPost, "/api/v1/auth/login", map[string]string{"email": cfg.SeedEmail, "password": cfg.SeedPassword, "otp": good})
	if code == http.StatusOK && strings.Contains(string(body), "csrf_token") {
		t.Fatal("verbrauchter Code darf nicht erneut anmelden")
	}
}
