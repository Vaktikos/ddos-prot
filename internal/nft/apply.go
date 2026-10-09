package nft

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Counter is a named nftables counter as reported by the kernel.
type Counter struct {
	Packets uint64
	Bytes   uint64
}

// Applier validates and atomically replaces the Sentinel Shield table. It keeps the
// last applied ruleset on disk so a failed apply can be rolled back.
type Applier struct {
	Nft      string // path to the nft binary
	Table    string
	StateDir string
	Timeout  time.Duration
}

// NewApplier returns an applier with default settings.
func NewApplier(stateDir string) *Applier {
	return &Applier{Nft: "nft", Table: DefaultTable, StateDir: stateDir, Timeout: 20 * time.Second}
}

// Check validates a script with the kernel parser without changing any rule.
func (a *Applier) Check(script string) error {
	path, err := a.writeTemp("candidate-*.nft", script)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	if _, err := a.run(context.Background(), "-c", "-f", path); err != nil {
		return fmt.Errorf("nftables-Validierung fehlgeschlagen: %w", err)
	}
	return nil
}

// Apply validates and loads the script as one kernel transaction. If loading
// fails, the previously applied table is restored. The previous table is read
// from the kernel, not from disk, so a crash cannot leave a stale backup in use.
func (a *Applier) Apply(script string) error {
	if err := a.Check(script); err != nil {
		return err
	}
	previous, hadPrevious, err := a.snapshot()
	if err != nil {
		return err
	}
	path, err := a.writeTemp("apply-*.nft", script)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	if _, err := a.run(context.Background(), "-f", path); err != nil {
		if hadPrevious {
			if rerr := a.restore(previous); rerr != nil {
				return fmt.Errorf("anwenden fehlgeschlagen (%v) und Rollback fehlgeschlagen: %w", err, rerr)
			}
			return fmt.Errorf("anwenden fehlgeschlagen, vorheriger Stand wiederhergestellt: %w", err)
		}
		return fmt.Errorf("anwenden fehlgeschlagen: %w", err)
	}
	return a.writeState("current.nft", script)
}

// Remove deletes the Sentinel Shield table. Used only on explicit uninstall or
// emergency stop; a running agent never removes its own protection on failure.
func (a *Applier) Remove() error {
	_, err := a.run(context.Background(), "delete", "table", "inet", a.Table)
	return err
}

// Counters reads all named counters of the table.
func (a *Applier) Counters() (map[string]Counter, error) {
	out, err := a.run(context.Background(), "-j", "list", "counters", "table", "inet", a.Table)
	if err != nil {
		return nil, err
	}
	return ParseCounters(out)
}

// SetSize returns the number of elements currently in a set of the table.
func (a *Applier) SetSize(set string) (int, error) {
	out, err := a.run(context.Background(), "-j", "list", "set", "inet", a.Table, set)
	if err != nil {
		return 0, err
	}
	return ParseSetElements(out)
}

// Installed reports whether the table currently exists in the kernel.
func (a *Applier) Installed() bool {
	_, err := a.run(context.Background(), "list", "table", "inet", a.Table)
	return err == nil
}

func (a *Applier) snapshot() (string, bool, error) {
	if !a.Installed() {
		return "", false, nil
	}
	out, err := a.run(context.Background(), "list", "table", "inet", a.Table)
	if err != nil {
		return "", false, fmt.Errorf("aktuellen Stand nicht lesbar: %w", err)
	}
	return string(out), true, nil
}

func (a *Applier) restore(previous string) error {
	script := fmt.Sprintf("add table inet %s\ndelete table inet %s\n%s", a.Table, a.Table, previous)
	path, err := a.writeTemp("restore-*.nft", script)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	_, err = a.run(context.Background(), "-f", path)
	return err
}

func (a *Applier) run(ctx context.Context, args ...string) ([]byte, error) {
	timeout := a.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.Nft, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nft %v: %w: %s", args, err, bytes.TrimSpace(stderr.Bytes()))
	}
	return stdout.Bytes(), nil
}

func (a *Applier) writeTemp(pattern, content string) (string, error) {
	if err := os.MkdirAll(a.StateDir, 0o700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(a.StateDir, pattern)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		return "", err
	}
	if _, err := f.WriteString(content); err != nil {
		return "", err
	}
	return f.Name(), nil
}

func (a *Applier) writeState(name, content string) error {
	if err := os.MkdirAll(a.StateDir, 0o700); err != nil {
		return err
	}
	final := filepath.Join(a.StateDir, name)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

// ParseCounters decodes `nft -j list counters` output.
func ParseCounters(data []byte) (map[string]Counter, error) {
	var doc struct {
		Nftables []struct {
			Counter *struct {
				Name    string `json:"name"`
				Packets uint64 `json:"packets"`
				Bytes   uint64 `json:"bytes"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("nft-Zähler nicht lesbar: %w", err)
	}
	out := map[string]Counter{}
	for _, e := range doc.Nftables {
		if e.Counter != nil {
			out[e.Counter.Name] = Counter{Packets: e.Counter.Packets, Bytes: e.Counter.Bytes}
		}
	}
	return out, nil
}

// ParseSetElements counts the elements of `nft -j list set` output.
func ParseSetElements(data []byte) (int, error) {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return 0, fmt.Errorf("nft-Set nicht lesbar: %w", err)
	}
	for _, e := range doc.Nftables {
		if e.Set != nil {
			return len(e.Set.Elem), nil
		}
	}
	return 0, errors.New("kein Set in der Ausgabe")
}
