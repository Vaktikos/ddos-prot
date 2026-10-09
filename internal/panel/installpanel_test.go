package panel

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runPanelInstaller(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	all := append([]string{"../../scripts/install-panel.sh", "--no-start", "--dir", dir}, args...)
	out, err := exec.Command("bash", all...).CombinedOutput()
	return string(out), err
}

func parseEnv(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		env[k] = v
	}
	return env
}

func TestPanelInstallerWritesAConfigThePanelAccepts(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl fehlt")
	}
	dir := t.TempDir()
	out, err := runPanelInstaller(t, dir, "--domain", "panel.example.net", "--admin-email", "ops@example.net")
	if err != nil {
		t.Fatalf("Installer: %v\n%s", err, out)
	}
	env := parseEnv(t, filepath.Join(dir, ".env"))

	// Load it through the panel's own configuration code, with the container paths mapped.
	for k, v := range env {
		t.Setenv(k, v)
	}
	t.Setenv("PANEL_ADMIN_PASSWORD_FILE", filepath.Join(dir, "secrets", "admin-password.txt"))
	t.Setenv("PANEL_SIGNING_KEY_FILE", filepath.Join(dir, "signing.key"))
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("das Panel lehnt die erzeugte Konfiguration ab: %v", err)
	}
	if cfg.PublicURL != "https://panel.example.net:8443" || cfg.SeedEmail != "ops@example.net" || len(cfg.SeedPassword) < 12 {
		t.Fatalf("Werte falsch: %+v", cfg)
	}
	if len(env["POSTGRES_PASSWORD"]) < 40 || !strings.Contains(env["PANEL_DATABASE_URL"], env["POSTGRES_PASSWORD"]) {
		t.Fatal("Datenbank-Passwort muss lang und konsistent sein")
	}

	// Files: the .env and the key are private, the certificate is valid for the domain.
	if info, _ := os.Stat(filepath.Join(dir, ".env")); info.Mode().Perm() != 0o600 {
		t.Fatalf(".env hat Rechte %v", info.Mode().Perm())
	}
	certOut, err := exec.Command("openssl", "x509", "-in", filepath.Join(dir, "secrets", "panel-cert.pem"), "-noout", "-subject", "-ext", "subjectAltName").CombinedOutput()
	if err != nil || !strings.Contains(string(certOut), "panel.example.net") {
		t.Fatalf("Zertifikat: %v %s", err, certOut)
	}

	// A second run keeps everything.
	before, _ := os.ReadFile(filepath.Join(dir, ".env"))
	out, err = runPanelInstaller(t, dir, "--domain", "other.example.net")
	if err != nil || !strings.Contains(out, "bleibt unverändert") {
		t.Fatalf("zweiter Lauf: %v\n%s", err, out)
	}
	after, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if string(before) != string(after) {
		t.Fatal("eine vorhandene .env darf nicht überschrieben werden")
	}

	// Two fresh installations never share secrets.
	other := t.TempDir()
	if _, err := runPanelInstaller(t, other, "--domain", "panel.example.net"); err != nil {
		t.Fatal(err)
	}
	if parseEnv(t, filepath.Join(other, ".env"))["POSTGRES_PASSWORD"] == env["POSTGRES_PASSWORD"] {
		t.Fatal("Geheimnisse müssen je Installation zufällig sein")
	}
}

func TestPanelInstallerRejectsBadInput(t *testing.T) {
	for name, args := range map[string][]string{
		"domain mit Metazeichen": {"--domain", "a;rm -rf /"},
		"ungültiger Port":        {"--domain", "panel.example.net", "--port", "70000"},
		"ungültige E-Mail":       {"--domain", "panel.example.net", "--admin-email", "kein-at"},
		"cert ohne key":          {"--domain", "panel.example.net", "--cert", "/nonexistent"},
	} {
		dir := t.TempDir()
		if out, err := runPanelInstaller(t, dir, args...); err == nil {
			t.Errorf("%s: wurde akzeptiert\n%s", name, out)
		}
		if _, err := os.Stat(filepath.Join(dir, ".env")); err == nil {
			t.Errorf("%s: .env darf bei ungültiger Eingabe nicht entstehen", name)
		}
	}
}
