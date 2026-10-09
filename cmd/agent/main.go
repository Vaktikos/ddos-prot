// Command sentinel-agent is the Sentinel Shield protection agent for Linux hosts.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/vaktikos/ddos-prot/internal/agent"
	"github.com/vaktikos/ddos-prot/internal/metrics"
	"github.com/vaktikos/ddos-prot/internal/nft"
	"github.com/vaktikos/ddos-prot/internal/xdp"
)

const usage = `sentinel-agent %s

Befehle:
  enroll  --config PFAD --token TOKEN [--force]   Node beim Panel registrieren
  check   --config PFAD                            Konfiguration und nftables prüfen (ändert nichts)
  run     --config PFAD                            Schutzdienst starten (systemd)
  xdp-detach --config PFAD                         XDP-Filter bewusst von allen Interfaces entfernen
  version                                          Version ausgeben
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, agent.Version)
		os.Exit(2)
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	var err error
	switch os.Args[1] {
	case "enroll":
		err = cmdEnroll(os.Args[2:])
	case "check":
		err = cmdCheck(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:], log)
	case "xdp-detach":
		err = cmdXDPDetach(os.Args[2:])
	case "version":
		fmt.Println(agent.Version)
	default:
		fmt.Fprintf(os.Stderr, usage, agent.Version)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fehler:", err)
		os.Exit(1)
	}
}

func loadConfig(fs *flag.FlagSet, args []string) (agent.Config, error) {
	cfgPath := fs.String("config", "/etc/sentinel-shield/agent.json", "Pfad zur Konfiguration")
	if err := fs.Parse(args); err != nil {
		return agent.Config{}, err
	}
	return agent.LoadConfig(*cfgPath)
}

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	token := fs.String("token", "", "einmaliger Enrollment-Token aus dem Panel")
	force := fs.Bool("force", false, "vorhandene Registrierung überschreiben")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	if *token == "" {
		return fmt.Errorf("--token fehlt")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := agent.Enroll(ctx, cfg, strings.TrimSpace(*token), *force); err != nil {
		return err
	}
	fmt.Println("Enrollment erfolgreich. Der Dienst kann mit 'systemctl start sentinel-agent' gestartet werden.")
	return nil
}

// cmdCheck validates the configuration and the firewall backend without changing rules.
func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	fmt.Println("konfiguration: ok")
	app := nft.NewApplier(cfg.StateDir)
	app.Nft = cfg.NftBinary
	app.Table = cfg.NftTable
	if _, err := app.Counters(); err != nil && app.Installed() {
		return fmt.Errorf("nftables-Zähler nicht lesbar: %w", err)
	}
	probe := "table inet " + cfg.NftTable + " {}\n"
	if err := app.Check(probe); err != nil {
		return fmt.Errorf("nftables nicht nutzbar (root und nft erforderlich): %w", err)
	}
	fmt.Println("nftables: ok")
	if _, err := metrics.ReadFile(metrics.ProcNetDev, metrics.ReadNetDev); err != nil {
		return fmt.Errorf("procfs nicht lesbar: %w", err)
	}
	fmt.Println("procfs: ok")
	return nil
}

// cmdXDPDetach removes the pinned XDP filter. The agent never does this on its own.
func cmdXDPDetach(args []string) error {
	fs := flag.NewFlagSet("xdp-detach", flag.ExitOnError)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	m, err := xdp.Load()
	if err != nil {
		return err
	}
	defer m.Close()
	if err := m.Detach(cfg.XDPPinDir, cfg.XDPInterfaces); err != nil {
		return err
	}
	fmt.Println("XDP-Filter entfernt")
	return nil
}

func cmdRun(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	client, err := agent.NewPanelClient(cfg.PanelURL, cfg.CAFile)
	if err != nil {
		return err
	}
	app := nft.NewApplier(cfg.StateDir)
	app.Nft = cfg.NftBinary
	app.Table = cfg.NftTable
	a, err := agent.New(cfg, log, app, agent.HostSampler(cfg.UplinkInterfaces), client)
	if err != nil {
		return err
	}
	if m, err := enableXDP(cfg, a, log); err != nil {
		log.Error("xdp nicht aktiviert, nftables-Schutz läuft weiter", "err", err)
	} else if m != nil {
		defer m.Close() // pinned links stay attached; only the process handles are released
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	log.Info("sentinel-agent gestartet", "version", agent.Version, "panel", cfg.PanelURL)
	// Shutdown deliberately leaves the firewall in place: protection must not stop with the agent.
	return a.Run(ctx)
}
