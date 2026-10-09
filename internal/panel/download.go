package panel

import (
	"embed"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

//go:embed assets/install-agent.sh assets/sentinel-agent.service assets/agent.example.json
var assets embed.FS

// downloadName allows exactly the files the installer needs. Nothing from the request is
// ever joined into a path unless it matches this expression.
var downloadName = regexp.MustCompile(`^(sentinel-agent-linux-(amd64|arm64)|SHA256SUMS)$`)

// installScript serves the agent installer with the panel's own address filled in, so the
// one-line command shown after creating a node works without further arguments.
func (a *App) installScript(w http.ResponseWriter, r *http.Request) {
	if !a.apiRL.allow(clientIP(r).String()) {
		writeErr(w, http.StatusTooManyRequests, "zu viele Anfragen")
		return
	}
	raw, err := assets.ReadFile("assets/install-agent.sh")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "installer nicht verfügbar")
		return
	}
	script := strings.ReplaceAll(string(raw), "@PANEL_URL@", strings.TrimRight(a.cfg.PublicURL, "/"))
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_, _ = w.Write([]byte(script))
}

// download serves agent binaries and checksums from PANEL_DOWNLOAD_DIR, plus the embedded
// systemd unit and example configuration.
func (a *App) download(w http.ResponseWriter, r *http.Request) {
	if !a.apiRL.allow(clientIP(r).String()) {
		writeErr(w, http.StatusTooManyRequests, "zu viele Anfragen")
		return
	}
	name := r.PathValue("name")
	switch name {
	case "sentinel-agent.service", "agent.example.json":
		raw, err := assets.ReadFile("assets/" + name)
		if err != nil {
			writeErr(w, http.StatusNotFound, "nicht gefunden")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(raw)
		return
	}
	if !downloadName.MatchString(name) || a.cfg.DownloadDir == "" {
		writeErr(w, http.StatusNotFound, "nicht gefunden")
		return
	}
	path := filepath.Join(a.cfg.DownloadDir, name)
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		writeErr(w, http.StatusNotFound, "diese Datei steht auf diesem Panel nicht bereit")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, path)
}
