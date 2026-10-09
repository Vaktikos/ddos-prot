package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/vaktikos/ddos-prot/internal/identity"
	"github.com/vaktikos/ddos-prot/internal/policy"
)

// HTTPError is returned for any non-200 panel answer, so callers can react to the status.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("panel antwortet %d: %s", e.Status, e.Body) }

// PanelClient talks to the panel. Requests after enrollment are signed with the
// node's Ed25519 key, and responses are only trusted through signed envelopes.
type PanelClient struct {
	base string
	http *http.Client
}

// NewPanelClient builds a client; caFile, if set, pins an additional trust root.
func NewPanelClient(baseURL, caFile string) (*PanelClient, error) {
	if !strings.HasPrefix(baseURL, "https://") && !strings.HasPrefix(baseURL, "http://127.0.0.1") && !strings.HasPrefix(baseURL, "http://localhost") {
		return nil, fmt.Errorf("panel_url muss https verwenden: %s", baseURL)
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file enthält keine Zertifikate")
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	return &PanelClient{base: strings.TrimRight(baseURL, "/"), http: &http.Client{Timeout: 15 * time.Second, Transport: tr}}, nil
}

// Enroll registers the node with a one-time token and returns the node ID and the panel's public key.
func (c *PanelClient) Enroll(ctx context.Context, token string, pub ed25519.PublicKey, hostname, version string) (NodeFile, error) {
	var out NodeFile
	body := map[string]string{
		"token":      token,
		"public_key": encodeB64(pub),
		"hostname":   hostname,
		"version":    version,
	}
	if err := c.doJSON(ctx, http.MethodPost, "/agent/v1/enroll", body, &out, nil); err != nil {
		return out, err
	}
	if out.NodeID == "" || out.PanelPublicKey == "" {
		return out, fmt.Errorf("enrollment-antwort unvollständig")
	}
	return out, nil
}

// Heartbeat sends a signed status report and returns the panel's instructions.
func (c *PanelClient) Heartbeat(ctx context.Context, nodeID string, priv ed25519.PrivateKey, hb Heartbeat) (HeartbeatReply, error) {
	var out HeartbeatReply
	err := c.signedJSON(ctx, nodeID, priv, http.MethodPost, "/agent/v1/heartbeat", hb, &out)
	return out, err
}

// FetchPolicy downloads the signed policy envelope for the node.
func (c *PanelClient) FetchPolicy(ctx context.Context, nodeID string, priv ed25519.PrivateKey) (policy.Envelope, error) {
	var env policy.Envelope
	err := c.signedJSON(ctx, nodeID, priv, http.MethodGet, "/agent/v1/policy", nil, &env)
	return env, err
}

// RotateKey tells the panel to replace the node's public key. The request is signed with the old key.
func (c *PanelClient) RotateKey(ctx context.Context, nodeID string, priv ed25519.PrivateKey, newPub ed25519.PublicKey) error {
	return c.signedJSON(ctx, nodeID, priv, http.MethodPost, "/agent/v1/rotate-key", map[string]string{"public_key": encodeB64(newPub)}, nil)
}

func (c *PanelClient) signedJSON(ctx context.Context, nodeID string, priv ed25519.PrivateKey, method, path string, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		body, err = json.Marshal(in)
		if err != nil {
			return err
		}
	}
	return c.doJSON(ctx, method, path, body, out, func(req *http.Request) error {
		return identity.Sign(req, nodeID, priv, body, time.Now())
	})
}

func (c *PanelClient) doJSON(ctx context.Context, method, path string, in any, out any, sign func(*http.Request) error) error {
	var body []byte
	switch v := in.(type) {
	case nil:
	case []byte:
		body = v
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		body = b
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "sentinel-agent")
	if sign != nil {
		if err := sign(req); err != nil {
			return err
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("panel nicht erreichbar: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return &HTTPError{Status: resp.StatusCode, Body: strings.TrimSpace(string(data))}
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("antwort nicht lesbar: %w", err)
		}
	}
	return nil
}
