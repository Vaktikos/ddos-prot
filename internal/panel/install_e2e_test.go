package panel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/vaktikos/ddos-prot/internal/agent"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestInstallScriptEndToEnd runs the real installer against a real panel: it downloads the
// agent, verifies its SHA-256, writes the configuration, checks nftables and enrolls the node.
// It installs below a staging root, so systemd and the host's /etc stay untouched.
func TestInstallScriptEndToEnd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root erforderlich (der Installer prüft nftables)")
	}
	tp := startTestPanel(t)

	// Build the agent exactly as the release does.
	dl := t.TempDir()
	bin := filepath.Join(dl, "sentinel-agent-linux-"+goArch())
	build := exec.Command("go", "build", "-o", bin, "../../cmd/agent")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("agent bauen: %v\n%s", err, out)
	}
	sum := func() string {
		raw, _ := os.ReadFile(bin)
		h := sha256.Sum256(raw)
		return hex.EncodeToString(h[:])
	}
	writeSums := func(hash string) {
		_ = os.WriteFile(filepath.Join(dl, "SHA256SUMS"), []byte(hash+"  sentinel-agent-linux-"+goArch()+"\n"), 0o644)
	}
	writeSums(sum())
	tp.app.cfg.DownloadDir = dl

	script := filepath.Join(t.TempDir(), "install.sh")
	code, body := tp.admin.call(http.MethodGet, "/install.sh", nil)
	mustOK(t, "install.sh", code, body, http.StatusOK)
	_ = os.WriteFile(script, body, 0o755)

	run := func(root, token string) (string, error) {
		args := []string{script, "--root", root, "--yes", "--uplink", "lo", "--management-cidr", "203.0.113.10/32",
			"--l7-log", "web,/var/log/nginx/ss_reject.log,192.0.2.10/32", "--mc-guard", "mc,9199,192.0.2.11"}
		if token != "" {
			args = append(args, "--token", token)
		}
		cmd := exec.Command("bash", args...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// 1. A tampered binary must be refused and nothing installed.
	writeSums(strings.Repeat("0", 64))
	badRoot := t.TempDir()
	out, err := run(badRoot, "")
	if err == nil || !strings.Contains(out, "Prüfsumme stimmt nicht") {
		t.Fatalf("falsche Prüfsumme muss abbrechen:\n%s", out)
	}
	if _, statErr := os.Stat(filepath.Join(badRoot, "usr/local/bin/sentinel-agent")); statErr == nil {
		t.Fatal("bei falscher Prüfsumme darf nichts installiert werden")
	}

	// 2. Correct checksum: install, check, enroll.
	writeSums(sum())
	code, body = tp.admin.call(http.MethodPost, "/api/v1/nodes", map[string]any{"name": "installed", "management_cidrs": []string{"203.0.113.10/32"}})
	mustOK(t, "node", code, body, http.StatusCreated)
	var created struct {
		Node  NodeDTO `json:"node"`
		Token string  `json:"enrollment_token"`
	}
	_ = json.Unmarshal(body, &created)

	root := t.TempDir()
	out, err = run(root, created.Token)
	if err != nil {
		t.Fatalf("Installation fehlgeschlagen: %v\n%s", err, out)
	}
	if !strings.Contains(out, "SHA-256 geprüft") {
		t.Fatalf("Prüfsumme muss geprüft werden:\n%s", out)
	}
	cfgRaw, err := os.ReadFile(filepath.Join(root, "etc/sentinel-shield/agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
		t.Fatalf("agent.json ist kein gültiges JSON: %v\n%s", err, cfgRaw)
	}
	if cfg["panel_url"] != tp.base || cfg["management_cidrs"].([]any)[0] != "203.0.113.10/32" {
		t.Fatalf("Konfiguration falsch: %s", cfgRaw)
	}
	loaded, err := agent.LoadConfig(filepath.Join(root, "etc/sentinel-shield/agent.json"))
	if err != nil {
		t.Fatalf("der Agent muss die erzeugte Konfiguration akzeptieren: %v\n%s", err, cfgRaw)
	}
	if len(loaded.L7Sources) != 1 || loaded.L7Sources[0].Path != "/var/log/nginx/ss_reject.log" ||
		len(loaded.MinecraftGuards) != 1 || loaded.MinecraftGuards[0].StatsURL != "http://127.0.0.1:9199/stats" {
		t.Fatalf("L7/Guard-Konfiguration falsch: %+v", loaded)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/sentinel-shield/node.json")); err != nil {
		t.Fatalf("Node wurde nicht registriert:\n%s", out)
	}
	code, body = tp.admin.call(http.MethodGet, "/api/v1/nodes/"+created.Node.ID, nil)
	mustOK(t, "node lesen", code, body, http.StatusOK)
	var n NodeDTO
	_ = json.Unmarshal(body, &n)
	if !n.Enrolled {
		t.Fatal("das Panel muss den Node als eingeschrieben führen")
	}

	// 3. Running it again keeps the configuration and does not enroll twice.
	before := string(cfgRaw)
	if out, err := run(root, created.Token); err != nil || !strings.Contains(out, "bleibt unverändert") {
		t.Fatalf("zweiter Lauf muss idempotent sein: %v\n%s", err, out)
	}
	after, _ := os.ReadFile(filepath.Join(root, "etc/sentinel-shield/agent.json"))
	if string(after) != before {
		t.Fatal("vorhandene Konfiguration wurde überschrieben")
	}
	_ = context.Background
}

func goArch() string {
	out, _ := exec.Command("go", "env", "GOARCH").Output()
	return strings.TrimSpace(string(out))
}
