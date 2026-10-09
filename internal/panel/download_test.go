package panel

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func downloadApp(t *testing.T) *App {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "sentinel-agent-linux-amd64"), []byte("binary-bytes"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte("abc  sentinel-agent-linux-amd64\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("do not serve"), 0o644)
	return &App{cfg: Config{PublicURL: "https://panel.example.net:8443", DownloadDir: dir}, apiRL: newLimiter(1000, 1000)}
}

func serve(a *App, path string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /install.sh", a.installScript)
	mux.HandleFunc("GET /download/{name}", a.download)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "192.0.2.5:1234"
	mux.ServeHTTP(rec, req)
	return rec
}

func TestInstallScriptCarriesPanelAddress(t *testing.T) {
	rec := serve(downloadApp(t), "/install.sh")
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), "#!/usr/bin/env bash") {
		t.Fatalf("install.sh: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `PANEL="https://panel.example.net:8443"`) || strings.Contains(rec.Body.String(), "@PANEL_URL@") {
		t.Fatal("die Panel-Adresse muss eingesetzt sein")
	}
}

func TestDownloadServesOnlyWhitelistedFiles(t *testing.T) {
	a := downloadApp(t)
	for path, want := range map[string]int{
		"/download/sentinel-agent-linux-amd64": http.StatusOK,
		"/download/SHA256SUMS":                 http.StatusOK,
		"/download/sentinel-agent.service":     http.StatusOK,
		"/download/agent.example.json":         http.StatusOK,
		"/download/sentinel-agent-linux-arm64": http.StatusNotFound, // allowed name, file absent
		"/download/secret.txt":                 http.StatusNotFound, // exists, not whitelisted
		"/download/..%2fsecret.txt":            http.StatusNotFound,
		"/download/sentinel-agent-linux-riscv": http.StatusNotFound,
	} {
		if got := serve(a, path).Code; got != want {
			t.Errorf("%s: HTTP %d, erwartet %d", path, got, want)
		}
	}
	if body := serve(a, "/download/sentinel-agent-linux-amd64").Body.String(); body != "binary-bytes" {
		t.Fatalf("Inhalt: %q", body)
	}
	a.cfg.DownloadDir = ""
	if serve(a, "/download/SHA256SUMS").Code != http.StatusNotFound {
		t.Fatal("ohne Download-Verzeichnis darf nichts ausgeliefert werden")
	}
}
