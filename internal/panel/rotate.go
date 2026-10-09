package panel

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
)

// requestKeyRotation marks a node so that its agent replaces its key at the next heartbeat.
func (a *App) requestKeyRotation(w http.ResponseWriter, r *http.Request, actor Actor) {
	tag, err := a.db.Exec(r.Context(), `UPDATE nodes SET rotate_key_requested = true, updated_at = now()
		WHERE id = $1::uuid AND public_key IS NOT NULL AND status <> 'revoked'`, r.PathValue("id"))
	if err != nil || tag.RowsAffected() == 0 {
		writeErr(w, http.StatusConflict, "node ist nicht eingeschrieben, widerrufen oder unbekannt")
		return
	}
	a.audit(r.Context(), a.db, "user", actor.UserID, "node.rotate_key_requested", "node", r.PathValue("id"), nil, ipString(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "rotation beim nächsten Heartbeat"})
}

type rotateRequest struct {
	PublicKey string `json:"public_key"`
}

// agentRotateKey swaps the node's public key. The request is signed with the current key,
// and it is accepted only while an administrator has requested a rotation.
func (a *App) agentRotateKey(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "body nicht lesbar")
		return
	}
	nodeID, ok := a.authenticateAgent(w, r, body)
	if !ok {
		return
	}
	var req rotateRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "ungültiger Body")
		return
	}
	pub, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		writeErr(w, http.StatusBadRequest, "ungültiger Schlüssel")
		return
	}
	ctx := r.Context()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE nodes SET public_key = $2, rotate_key_requested = false, updated_at = now()
		WHERE id = $1::uuid AND rotate_key_requested = true`, nodeID, []byte(pub))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	if tag.RowsAffected() == 0 {
		writeErr(w, http.StatusConflict, "keine Rotation angefordert")
		return
	}
	a.audit(ctx, tx, "node", nodeID, "node.key_rotated", "node", nodeID, nil, ipString(r))
	if err := tx.Commit(ctx); err != nil {
		writeErr(w, http.StatusInternalServerError, "interner Fehler")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "schlüssel ersetzt"})
}
