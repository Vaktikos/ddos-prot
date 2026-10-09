package panel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 mandates HMAC-SHA1; this is not a collision-sensitive use
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	totpStep   = 30 // seconds
	totpDigits = 6
	totpSkew   = 1 // accept one step before and after, for clock drift
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// totpAt computes the RFC 6238 code for one time step.
func totpAt(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%0*d", totpDigits, code%1000000)
}

// verifyTOTP returns the accepted step, or -1. Steps at or before lastStep are rejected
// so that a code that was used once cannot be used again.
func verifyTOTP(secret []byte, code string, now time.Time, lastStep int64) int64 {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return -1
	}
	current := now.Unix() / totpStep
	for d := -totpSkew; d <= totpSkew; d++ {
		step := current + int64(d)
		if step <= lastStep {
			continue
		}
		if hmac.Equal([]byte(totpAt(secret, step)), []byte(code)) {
			return step
		}
	}
	return -1
}

// mfaKey derives the encryption key for stored TOTP secrets from the panel's signing key.
// Losing the signing key therefore also makes stored MFA secrets unreadable (see OPERATIONS.md).
func (a *App) mfaKey() []byte {
	h := sha256.New()
	h.Write([]byte("sentinel-shield mfa v1"))
	h.Write(a.priv.Seed())
	return h.Sum(nil)
}

func (a *App) sealSecret(secret []byte) (string, error) {
	block, err := aes.NewCipher(a.mfaKey())
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, secret, nil)), nil
}

func (a *App) openSecret(enc string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(a.mfaKey())
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("geheimnis zu kurz")
	}
	return gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
}

// mfaEnroll creates a new pending secret. MFA stays off until mfaEnable confirms a code.
func (a *App) mfaEnroll(w http.ResponseWriter, r *http.Request, actor Actor) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	enc, err := a.sealSecret(secret)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	tag, err := a.db.Exec(r.Context(), `UPDATE users SET totp_secret_enc = $2 WHERE id = $1::uuid AND totp_enabled = false`,
		actor.UserID, enc)
	if err != nil || tag.RowsAffected() == 0 {
		writeErr(w, http.StatusConflict, "mfa ist bereits aktiv; zum Ändern zuerst deaktivieren")
		return
	}
	s := b32.EncodeToString(secret)
	uri := fmt.Sprintf("otpauth://totp/Sentinel%%20Shield:%s?secret=%s&issuer=Sentinel%%20Shield&digits=6&period=30",
		actor.Email, s)
	writeJSON(w, http.StatusOK, map[string]string{"secret": s, "otpauth_uri": uri})
}

type otpRequest struct {
	Code string `json:"code"`
}

// mfaEnable confirms the pending secret with one valid code.
func (a *App) mfaEnable(w http.ResponseWriter, r *http.Request, actor Actor) {
	var req otpRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	secret, step, ok := a.userSecret(r, actor.UserID)
	if !ok {
		writeErr(w, http.StatusConflict, "kein ausstehendes mfa-geheimnis, zuerst einrichten")
		return
	}
	accepted := verifyTOTP(secret, req.Code, a.now(), step)
	if accepted < 0 {
		writeErr(w, http.StatusUnauthorized, "code ungültig")
		return
	}
	_, err := a.db.Exec(r.Context(), `UPDATE users SET totp_enabled = true, totp_last_step = $2 WHERE id = $1::uuid`, actor.UserID, accepted)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	a.audit(r.Context(), a.db, "user", actor.UserID, "mfa.enable", "user", actor.UserID, nil, ipString(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "mfa aktiv"})
}

// mfaDisable turns MFA off; it requires a current code so a stolen session alone cannot do it.
func (a *App) mfaDisable(w http.ResponseWriter, r *http.Request, actor Actor) {
	var req otpRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	secret, step, ok := a.userSecret(r, actor.UserID)
	if !ok || verifyTOTP(secret, req.Code, a.now(), step) < 0 {
		writeErr(w, http.StatusUnauthorized, "code ungültig")
		return
	}
	_, _ = a.db.Exec(r.Context(), `UPDATE users SET totp_enabled = false, totp_secret_enc = NULL, totp_last_step = 0 WHERE id = $1::uuid`, actor.UserID)
	a.audit(r.Context(), a.db, "user", actor.UserID, "mfa.disable", "user", actor.UserID, nil, ipString(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "mfa deaktiviert"})
}

func (a *App) userSecret(r *http.Request, userID string) ([]byte, int64, bool) {
	var enc *string
	var step int64
	if err := a.db.QueryRow(r.Context(), `SELECT totp_secret_enc, totp_last_step FROM users WHERE id = $1::uuid`, userID).Scan(&enc, &step); err != nil || enc == nil {
		return nil, 0, false
	}
	secret, err := a.openSecret(*enc)
	if err != nil {
		return nil, 0, false
	}
	return secret, step, true
}

// mfaRequiredBody is the login answer when the password was correct but a second factor is needed.
func mfaRequiredBody() []byte {
	b, _ := json.Marshal(map[string]any{"mfa_required": true})
	return b
}
