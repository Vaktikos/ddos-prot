package panel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/argon2"
)

// Password hashing parameters (OWASP baseline for argon2id).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 2
	argonKeyLen  = 32

	minPasswordLen = 12
	maxPasswordLen = 256

	sessionCookie   = "ss_session"
	sessionIdle     = 30 * time.Minute
	maxFailedLogins = 5
	lockoutDuration = 15 * time.Minute
)

// HashPassword returns an encoded argon2id hash with a random salt.
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks a password against an encoded argon2id hash in constant time.
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var mem, iter uint32
	var par uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iter, &par); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, iter, mem, par, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func validPassword(p string) error {
	if len(p) < minPasswordLen {
		return fmt.Errorf("passwort muss mindestens %d Zeichen haben", minPasswordLen)
	}
	if len(p) > maxPasswordLen {
		return errors.New("passwort ist zu lang")
	}
	return nil
}

func randomToken(n int) (string, []byte, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	tok := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(tok))
	return tok, sum[:], nil
}

func tokenHash(tok string) []byte {
	sum := sha256.Sum256([]byte(tok))
	return sum[:]
}

// EnsureSeedAdmin creates the first administrator if no user exists yet.
func (a *App) EnsureSeedAdmin(ctx context.Context) error {
	var n int
	if err := a.db.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if a.cfg.SeedEmail == "" || a.cfg.SeedPassword == "" {
		return errors.New("kein Benutzer vorhanden: PANEL_ADMIN_EMAIL und PANEL_ADMIN_PASSWORD_FILE setzen")
	}
	if err := validPassword(a.cfg.SeedPassword); err != nil {
		return err
	}
	hash, err := HashPassword(a.cfg.SeedPassword)
	if err != nil {
		return err
	}
	var id string
	if err := a.db.QueryRow(ctx, `INSERT INTO users (email, password_hash, role) VALUES (lower($1), $2, 'admin') RETURNING id::text`,
		a.cfg.SeedEmail, hash).Scan(&id); err != nil {
		return err
	}
	a.audit(ctx, a.db, "system", "bootstrap", "user.create", "user", id, map[string]any{"role": RoleAdmin, "reason": "erster Start"}, nil)
	a.log.Info("erster Administrator angelegt", "email", a.cfg.SeedEmail)
	return nil
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	OTP      string `json:"otp,omitempty"`
}

// dummyHash keeps the timing of unknown-user logins close to real ones.
var dummyHash, _ = HashPassword("dummy-password-for-timing-only")

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r).String()
	if !a.loginRL.allow(ip) {
		writeErr(w, http.StatusTooManyRequests, "zu viele Anmeldeversuche")
		return
	}
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	ctx := r.Context()

	var id, role, hash string
	var disabled, totpOn bool
	var failed int
	var locked *time.Time
	var lastStep int64
	err := a.db.QueryRow(ctx, `SELECT id::text, role, password_hash, disabled, failed_logins, locked_until, totp_enabled, totp_last_step
		FROM users WHERE email = $1`, email).
		Scan(&id, &role, &hash, &disabled, &failed, &locked, &totpOn, &lastStep)
	if errors.Is(err, pgx.ErrNoRows) {
		VerifyPassword(req.Password, dummyHash)
		writeErr(w, http.StatusUnauthorized, "anmeldung fehlgeschlagen")
		return
	}
	if err != nil {
		a.log.Error("login: datenbankfehler", "err", err)
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	now := a.now()
	if disabled || (locked != nil && locked.After(now)) || len(req.Password) > maxPasswordLen {
		writeErr(w, http.StatusUnauthorized, "anmeldung fehlgeschlagen")
		return
	}
	passwordOK := VerifyPassword(req.Password, hash)
	usedStep := int64(-1)
	if passwordOK && totpOn {
		if req.OTP == "" {
			// Password was right: ask for the second factor without counting a failure.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(mfaRequiredBody())
			return
		}
		secret, _, ok := a.userSecret(r, id)
		if ok {
			usedStep = verifyTOTP(secret, req.OTP, now, lastStep)
		}
		if usedStep < 0 {
			passwordOK = false
		}
	}
	if !passwordOK {
		failed++
		var lockUntil *time.Time
		if failed >= maxFailedLogins {
			t := now.Add(lockoutDuration)
			lockUntil = &t
			failed = 0
		}
		_, _ = a.db.Exec(ctx, `UPDATE users SET failed_logins = $2, locked_until = $3 WHERE id = $1`, id, failed, lockUntil)
		a.audit(ctx, a.db, "user", id, "auth.login_failed", "user", id, map[string]any{"locked": lockUntil != nil}, ipString(r))
		writeErr(w, http.StatusUnauthorized, "anmeldung fehlgeschlagen")
		return
	}

	tok, hashed, err := randomToken(32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	csrf, _, err := randomToken(32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	expires := now.Add(time.Duration(a.cfg.SessionHours) * time.Hour)
	tx, err := a.db.Begin(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at, client_ip)
		VALUES ($1, $2::uuid, $3, $4, $5::inet)`, hashed, id, csrf, expires, ipString(r)); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = now(),
		totp_last_step = CASE WHEN $2::bigint >= 0 THEN $2::bigint ELSE totp_last_step END WHERE id = $1`, id, usedStep); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	a.audit(ctx, tx, "user", id, "auth.login", "user", id, nil, ipString(r))
	if err := tx.Commit(ctx); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true,
		Secure: a.cfg.CookieSecure, SameSite: http.SameSiteStrictMode,
		Expires: expires,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       map[string]string{"id": id, "email": email, "role": role},
		"csrf_token": csrf,
	})
}

func (a *App) logout(w http.ResponseWriter, r *http.Request, actor Actor) {
	c, err := r.Cookie(sessionCookie)
	if err == nil {
		_, _ = a.db.Exec(r.Context(), `DELETE FROM sessions WHERE token_hash = $1`, tokenHash(c.Value))
	}
	a.audit(r.Context(), a.db, "user", actor.UserID, "auth.logout", "user", actor.UserID, nil, ipString(r))
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: a.cfg.CookieSecure, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]string{"status": "abgemeldet"})
}

func (a *App) me(w http.ResponseWriter, _ *http.Request, actor Actor) {
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       map[string]string{"id": actor.UserID, "email": actor.Email, "role": actor.Role},
		"csrf_token": actor.CSRF,
	})
}

// sessionActor resolves the session cookie. Idle sessions expire after sessionIdle.
func (a *App) sessionActor(r *http.Request) (Actor, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return Actor{}, errors.New("kein Cookie")
	}
	now := a.now()
	var act Actor
	var lastSeen time.Time
	err = a.db.QueryRow(r.Context(), `
		SELECT u.id::text, u.email, u.role, s.csrf_token, s.last_seen_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.expires_at > $2 AND u.disabled = false`,
		tokenHash(c.Value), now).Scan(&act.UserID, &act.Email, &act.Role, &act.CSRF, &lastSeen)
	if err != nil {
		return Actor{}, errors.New("sitzung ungültig")
	}
	if now.Sub(lastSeen) > sessionIdle {
		_, _ = a.db.Exec(r.Context(), `DELETE FROM sessions WHERE token_hash = $1`, tokenHash(c.Value))
		return Actor{}, errors.New("sitzung abgelaufen")
	}
	if now.Sub(lastSeen) > time.Minute {
		_, _ = a.db.Exec(r.Context(), `UPDATE sessions SET last_seen_at = $2 WHERE token_hash = $1`, tokenHash(c.Value), now)
	}
	return act, nil
}
