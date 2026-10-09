package panel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/vaktikos/ddos-prot/internal/policy"
	"github.com/vaktikos/ddos-prot/internal/signer"
)

func (e *rotationEnv) publishTargetChange(t *testing.T, name, prefix string) {
	t.Helper()
	code, body := e.tp.admin.call(http.MethodPost, "/api/v1/nodes/"+e.nodeID+"/targets", map[string]any{
		"name": name, "prefix": prefix, "profile": "std"})
	mustOK(t, "ziel "+name, code, body, http.StatusCreated)
}

func (e *rotationEnv) node(t *testing.T) NodeDTO {
	t.Helper()
	code, body := e.tp.admin.call(http.MethodGet, "/api/v1/nodes/"+e.nodeID, nil)
	mustOK(t, "node", code, body, http.StatusOK)
	var n NodeDTO
	_ = json.Unmarshal(body, &n)
	return n
}

// The panel signing key is rotated without re-enrolling any agent: announce, wait until the
// node knows the next key, switch. Unannounced and retired keys must be refused.
func TestSigningKeyRotationWithoutReEnrollment(t *testing.T) {
	e := newRotationEnv(t)
	ctx := context.Background()
	tp := e.tp

	code, body := tp.admin.call(http.MethodPost, "/api/v1/profiles", map[string]any{"name": "std", "kind": "generic",
		"config": map[string]any{"syn_pps": 20000, "confirm_seconds": 3, "clear_seconds": 5}})
	mustOK(t, "profil", code, body, http.StatusCreated)

	key1 := tp.app.sg
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	key2 := signer.FromKey(priv2)
	_, priv3, _ := ed25519.GenerateKey(rand.Reader)
	key3 := signer.FromKey(priv3)

	e.publishTargetChange(t, "a", "192.0.2.10")
	if err := e.ag.Heartbeat(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if n := e.node(t); n.AppliedPolicyVersion != n.DesiredPolicyVersion || n.SyncStatus != "synced" {
		t.Fatalf("Ausgangszustand nicht synchron: %+v", n)
	}

	// Step 1: announce key2 while still signing with key1.
	tp.swapSigner(t, key1, pub2)
	if err := e.ag.Heartbeat(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := e.ag.Heartbeat(ctx, time.Now()); err != nil { // second one reports the learned keys
		t.Fatal(err)
	}
	code, body = tp.admin.call(http.MethodGet, "/api/v1/signing", nil)
	mustOK(t, "signing status", code, body, http.StatusOK)
	var st struct {
		Active, Next string
		Ready        bool   `json:"ready_to_switch"`
		ActiveID     string `json:"active_key_id"`
		NextID       string `json:"next_key_id"`
	}
	_ = json.Unmarshal(body, &st)
	if !st.Ready || st.NextID != policy.KeyID(pub2) {
		t.Fatalf("der Node muss den nächsten Schlüssel kennen: %s", body)
	}

	// Step 2: switch to key2. The policy is signed by key2 and the agent accepts it.
	tp.swapSigner(t, key2, nil)
	e.publishTargetChange(t, "b", "192.0.2.11")
	if err := e.ag.Heartbeat(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if n := e.node(t); n.AppliedPolicyVersion != n.DesiredPolicyVersion || n.SyncStatus != "synced" {
		t.Fatalf("nach dem Wechsel muss der Node die mit key2 signierte Policy übernehmen: %+v", n)
	}

	// Key1 is retired now: a policy signed by it is refused.
	tp.swapSigner(t, key1, nil)
	e.publishTargetChange(t, "c", "192.0.2.12")
	_ = e.ag.Heartbeat(ctx, time.Now())
	_ = e.ag.Heartbeat(ctx, time.Now())
	if n := e.node(t); n.AppliedPolicyVersion >= n.DesiredPolicyVersion {
		t.Fatalf("ein ausgemusterter Schlüssel darf keine Policy mehr durchsetzen: %+v", n)
	}

	// A key that was never announced is refused as well.
	tp.swapSigner(t, key3, nil)
	e.publishTargetChange(t, "d", "192.0.2.13")
	_ = e.ag.Heartbeat(ctx, time.Now())
	_ = e.ag.Heartbeat(ctx, time.Now())
	if n := e.node(t); n.AppliedPolicyVersion >= n.DesiredPolicyVersion {
		t.Fatalf("ein nie angekündigter Schlüssel darf keine Policy durchsetzen: %+v", n)
	}

	// Back on the legitimate key, the node recovers by itself.
	tp.swapSigner(t, key2, nil)
	e.publishTargetChange(t, "e", "192.0.2.14")
	_ = e.ag.Heartbeat(ctx, time.Now())
	_ = e.ag.Heartbeat(ctx, time.Now())
	if n := e.node(t); n.AppliedPolicyVersion != n.DesiredPolicyVersion {
		t.Fatalf("mit dem richtigen Schlüssel muss der Node wieder synchron werden: %+v", n)
	}
}
