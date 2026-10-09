// Command sentinel-panel runs the Sentinel Shield control plane: management API,
// agent API, policy signing and background maintenance.
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/vaktikos/ddos-prot/internal/panel"
	"github.com/vaktikos/ddos-prot/internal/store"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(log); err != nil {
		log.Error("panel beendet mit Fehler", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := panel.LoadConfig()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := store.Migrate(ctx, db); err != nil {
		return err
	}
	sg, err := panel.BuildSigner(cfg)
	if err != nil {
		return fmt.Errorf("signer %q: %w", cfg.Signer, err)
	}
	log.Info("signatur-backend bereit", "backend", sg.Describe())
	var app *panel.App
	if cfg.Signer == "file" && cfg.DataKeyFile == "" && cfg.NextPublicKey == "" {
		// Single-key setups keep working unchanged: MFA secrets stay tied to the signing key.
		_, priv, kerr := panel.LoadOrCreateSigningKey(cfg.SigningKey)
		if kerr != nil {
			return kerr
		}
		app, err = panel.New(cfg, db, log, sg.Public(), priv)
	} else {
		dkPath := cfg.DataKeyFile
		if dkPath == "" {
			dkPath = filepath.Join(filepath.Dir(cfg.SigningKey), "data.key")
		}
		dataKey, kerr := panel.LoadOrCreateDataKey(dkPath)
		if kerr != nil {
			return kerr
		}
		var next ed25519.PublicKey
		if cfg.NextPublicKey != "" {
			if next, kerr = panel.DecodePublicKey(cfg.NextPublicKey); kerr != nil {
				return fmt.Errorf("PANEL_NEXT_SIGNING_PUBLIC_KEY: %w", kerr)
			}
		}
		app, err = panel.NewWithSigner(cfg, db, log, sg, dataKey, next)
	}
	if err != nil {
		return err
	}
	if err := app.EnsureSeedAdmin(ctx); err != nil {
		return err
	}
	go app.RunJobs(ctx)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("panel läuft", "listen", cfg.Listen, "tls", cfg.TLSCert != "")
		if cfg.TLSCert != "" {
			errc <- srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
			return
		}
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}
