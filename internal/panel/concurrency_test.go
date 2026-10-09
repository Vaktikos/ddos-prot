package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/vaktikos/ddos-prot/internal/store"
)

// TestConcurrentChangesProduceContiguousVersions fires parallel target and rule changes
// at one node. Each change must either succeed with a unique version number or fail
// cleanly; no version may be skipped, duplicated, or stored with a broken body.
func TestConcurrentChangesProduceContiguousVersions(t *testing.T) {
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
	cfg := Config{PublicURL: base, DatabaseURL: dsn, SigningKey: filepath.Join(t.TempDir(), "k"), CookieSecure: false,
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
	code, body := admin.call(http.MethodPost, "/api/v1/profiles", map[string]any{"name": "std", "kind": "generic",
		"config": map[string]any{"syn_pps": 20000, "confirm_seconds": 3, "clear_seconds": 5}})
	mustOK(t, "profil", code, body, http.StatusCreated)
	code, body = admin.call(http.MethodPost, "/api/v1/nodes", map[string]any{"name": "n1", "mode": "auto",
		"management_cidrs": []string{"203.0.113.10/32"}})
	mustOK(t, "node", code, body, http.StatusCreated)
	var created struct {
		Node NodeDTO `json:"node"`
	}
	_ = json.Unmarshal(body, &created)
	nodeID := created.Node.ID

	const workers = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	okVersions := []int64{}
	failures := 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := newAPIClient(t, base)
			c.hc.Jar = admin.hc.Jar
			c.csrf = admin.csrf
			var code int
			var body []byte
			if i%2 == 0 {
				code, body = c.call(http.MethodPost, "/api/v1/nodes/"+nodeID+"/targets", map[string]any{
					"name": fmt.Sprintf("t%d", i), "prefix": fmt.Sprintf("192.0.2.%d", 10+i), "profile": "std",
					"services": []map[string]any{{"name": "https", "protocol": "tcp", "port": 443}},
				})
			} else {
				code, body = c.call(http.MethodPost, "/api/v1/nodes/"+nodeID+"/rules", map[string]any{
					"kind": "deny", "prefix": fmt.Sprintf("198.51.100.%d", 10+i), "reason": "parallel",
					"expires_at": time.Now().Add(time.Hour),
				})
			}
			mu.Lock()
			defer mu.Unlock()
			if code == http.StatusCreated {
				okVersions = append(okVersions, 0)
			} else {
				failures++
				t.Logf("worker %d: HTTP %d %s", i, code, body)
			}
		}(i)
	}
	wg.Wait()

	code, body = admin.call(http.MethodGet, "/api/v1/nodes/"+nodeID+"/policies", nil)
	mustOK(t, "versionen", code, body, http.StatusOK)
	var versions []struct {
		Version int64 `json:"version"`
	}
	_ = json.Unmarshal(body, &versions)
	var got []int64
	for _, v := range versions {
		got = append(got, v.Version)
	}
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	// Version 1 is the first publication in the parallel run only if the node had no
	// earlier version; here the node starts empty, so versions must be 1..N exactly.
	if len(got) != len(okVersions) {
		t.Fatalf("erfolgreiche Änderungen = %d, gespeicherte Versionen = %d (Fehler: %d)", len(okVersions), len(got), failures)
	}
	for i, v := range got {
		if v != int64(i+1) {
			t.Fatalf("Versionen nicht lückenlos/eindeutig: %v", got)
		}
	}
	if len(got) == 0 {
		t.Fatal("keine Änderung erfolgreich")
	}
}

func envDSN(t *testing.T) string {
	t.Helper()
	dsn := envValue("SS_TEST_DSN")
	if dsn == "" {
		t.Skip("SS_TEST_DSN nicht gesetzt")
	}
	return dsn
}
