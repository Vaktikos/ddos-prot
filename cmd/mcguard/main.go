// Command sentinel-mcguard is the Minecraft Java protection proxy. It listens on the public
// address, validates every connection's handshake and forwards valid ones to the game server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vaktikos/ddos-prot/internal/mcguard"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfgPath := flag.String("config", "/etc/sentinel-shield/mcguard.json", "Pfad zur Konfiguration")
	check := flag.Bool("check", false, "nur die Konfiguration prüfen")
	version := flag.Bool("version", false, "Version ausgeben")
	flag.Parse()
	if *version {
		fmt.Println(mcguard.Version)
		return
	}
	cfg, err := mcguard.LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fehler:", err)
		os.Exit(1)
	}
	srv, err := mcguard.New(cfg, log)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fehler:", err)
		os.Exit(1)
	}
	if *check {
		fmt.Println("konfiguration: ok")
		return
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fehler:", err)
		os.Exit(1)
	}
	statsSrv := &http.Server{Addr: cfg.StatsListen, Handler: srv.StatsHandler(), ReadHeaderTimeout: 3 * time.Second}
	go func() {
		if err := statsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("statistik-endpunkt beendet", "err", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("sentinel-mcguard gestartet", "listen", cfg.Listen, "backend", cfg.Backend, "proxy_protocol", cfg.ProxyProtocol, "version", mcguard.Version)
	if err := srv.Serve(ctx, ln); err != nil {
		log.Error("beendet mit Fehler", "err", err)
		os.Exit(1)
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = statsSrv.Shutdown(shutdown)
}
