package panel

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
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
	a := &App{legacy: legacyMFAKey(priv)}
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

func TestDataKeyIsIndependentOfSigningKeyAndLegacySecretsStayReadable(t *testing.T) {
	_, priv, _ := LoadOrCreateSigningKey(filepath.Join(t.TempDir(), "k"))
	dataKey, err := LoadOrCreateDataKey(filepath.Join(t.TempDir(), "data.key"))
	if err != nil {
		t.Fatal(err)
	}
	// A secret sealed the old way (derived from the signing seed).
	old := &App{legacy: legacyMFAKey(priv)}
	oldEnc, _ := old.sealSecret([]byte("legacy-secret-0123456"))

	upgraded := &App{dataKey: dataKey, legacy: legacyMFAKey(priv)}
	if dec, err := upgraded.openSecret(oldEnc); err != nil || string(dec) != "legacy-secret-0123456" {
		t.Fatalf("alte Geheimnisse müssen lesbar bleiben: %v", err)
	}
	newEnc, _ := upgraded.sealSecret([]byte("fresh-secret-0123456"))

	// With an HSM there is no seed: only the data key exists, and old secrets are unreadable.
	hsm := &App{dataKey: dataKey}
	if dec, err := hsm.openSecret(newEnc); err != nil || string(dec) != "fresh-secret-0123456" {
		t.Fatalf("neue Geheimnisse brauchen nur den Datenschlüssel: %v", err)
	}
	if _, err := hsm.openSecret(oldEnc); err == nil {
		t.Fatal("ohne Altschlüssel darf ein altes Geheimnis nicht lesbar sein")
	}
}

func TestDataKeyFileIsCreatedPrivateAndRejectsOpenPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d", "data.key")
	k1, err := LoadOrCreateDataKey(path)
	if err != nil || len(k1) != 32 {
		t.Fatalf("anlegen: %v", err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("Rechte = %v", info.Mode().Perm())
	}
	k2, _ := LoadOrCreateDataKey(path)
	if string(k1) != string(k2) {
		t.Fatal("der zweite Start muss denselben Schlüssel laden")
	}
	_ = os.Chmod(path, 0o644)
	if _, err := LoadOrCreateDataKey(path); err == nil {
		t.Fatal("zu offene Rechte müssen abgelehnt werden")
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

func TestRecoveryCodeFormatAndHashing(t *testing.T) {
	codes, hashes, err := newRecoveryCodes()
	if err != nil || len(codes) != recoveryCodeCount || len(hashes) != recoveryCodeCount {
		t.Fatalf("Anzahl: %v", err)
	}
	seen := map[string]bool{}
	for i, c := range codes {
		if len(c) != 14 || c[4] != '-' || c[9] != '-' || seen[c] {
			t.Fatalf("Format/Eindeutigkeit verletzt: %q", c)
		}
		seen[c] = true
		// Entry is forgiving about case, dashes and spaces.
		if string(hashRecoveryCode(strings.ToLower(strings.ReplaceAll(c, "-", " ")))) != string(hashes[i]) {
			t.Fatalf("Normalisierung greift nicht für %q", c)
		}
	}
}

func TestMFARecoveryCodesFlow(t *testing.T) {
	tp := startTestPanel(t)
	c := tp.admin
	code, body := c.call(http.MethodPost, "/api/v1/auth/mfa/enroll", nil)
	mustOK(t, "einrichten", code, body, http.StatusOK)
	var enroll struct {
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal(body, &enroll)
	secret, _ := b32.DecodeString(enroll.Secret)

	step := time.Now().Unix() / totpStep
	code, body = c.call(http.MethodPost, "/api/v1/auth/mfa/enable", map[string]string{"code": totpAt(secret, step)})
	mustOK(t, "aktivieren", code, body, http.StatusOK)
	var enabled struct {
		Codes []string `json:"recovery_codes"`
	}
	_ = json.Unmarshal(body, &enabled)
	if len(enabled.Codes) != recoveryCodeCount {
		t.Fatalf("beim Aktivieren müssen %d Codes ausgegeben werden: %s", recoveryCodeCount, body)
	}

	login := func(extra map[string]string) (int, string) {
		cl := newAPIClient(t, tp.base)
		payload := map[string]string{"email": tp.cfg.SeedEmail, "password": tp.cfg.SeedPassword}
		for k, v := range extra {
			payload[k] = v
		}
		code, b := cl.call(http.MethodPost, "/api/v1/auth/login", payload)
		return code, string(b)
	}

	// A recovery code signs in once and not twice.
	if code, b := login(map[string]string{"recovery_code": strings.ToLower(enabled.Codes[0])}); code != http.StatusOK || !strings.Contains(b, "csrf_token") {
		t.Fatalf("Recovery-Code muss anmelden: %d %s", code, b)
	}
	if code, b := login(map[string]string{"recovery_code": enabled.Codes[0]}); code == http.StatusOK && strings.Contains(b, "csrf_token") {
		t.Fatal("ein verbrauchter Recovery-Code darf nicht erneut gelten")
	}
	if code, b := login(map[string]string{"recovery_code": "AAAA-BBBB-CCCC"}); code != http.StatusUnauthorized {
		t.Fatalf("unbekannter Code muss abgelehnt werden: %d %s", code, b)
	}

	// /auth/me reports how many are left.
	code, body = c.call(http.MethodGet, "/api/v1/auth/me", nil)
	mustOK(t, "me", code, body, http.StatusOK)
	if !strings.Contains(string(body), `"recovery_codes_left":9`) || !strings.Contains(string(body), `"mfa_enabled":true`) {
		t.Fatalf("9 verbleibende Codes erwartet: %s", body)
	}

	// Regenerating needs a valid TOTP code and invalidates the old set.
	code, body = c.call(http.MethodPost, "/api/v1/auth/mfa/recovery", map[string]string{"code": "000000"})
	mustOK(t, "falscher code", code, body, http.StatusUnauthorized)
	code, body = c.call(http.MethodPost, "/api/v1/auth/mfa/recovery", map[string]string{"code": totpAt(secret, step+1)})
	mustOK(t, "neu erzeugen", code, body, http.StatusOK)
	var fresh struct {
		Codes []string `json:"recovery_codes"`
	}
	_ = json.Unmarshal(body, &fresh)
	if len(fresh.Codes) != recoveryCodeCount {
		t.Fatalf("neuer Satz: %s", body)
	}
	if code, b := login(map[string]string{"recovery_code": enabled.Codes[1]}); code == http.StatusOK && strings.Contains(b, "csrf_token") {
		t.Fatal("Codes des alten Satzes müssen ungültig sein")
	}
	if code, b := login(map[string]string{"recovery_code": fresh.Codes[0]}); code != http.StatusOK || !strings.Contains(b, "csrf_token") {
		t.Fatalf("Code des neuen Satzes muss gelten: %d %s", code, b)
	}

	// Disabling MFA removes the codes.
	// The replay guard allows one code per time step; reset it instead of waiting 30 seconds.
	if _, err := tp.pool.Exec(context.Background(), `UPDATE users SET totp_last_step = 0`); err != nil {
		t.Fatal(err)
	}
	code, body = c.call(http.MethodPost, "/api/v1/auth/mfa/disable", map[string]string{"code": totpAt(secret, time.Now().Unix()/totpStep)})
	mustOK(t, "deaktivieren", code, body, http.StatusOK)
	code, body = c.call(http.MethodGet, "/api/v1/auth/me", nil)
	if !strings.Contains(string(body), `"recovery_codes_left":0`) {
		t.Fatalf("nach dem Deaktivieren dürfen keine Codes übrig sein: %s", body)
	}
}
