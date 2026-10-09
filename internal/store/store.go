// Package store owns the PostgreSQL connection pool and the schema migrations.
package store

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Open connects to PostgreSQL and verifies the connection.
func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("datenbank-dsn ungültig: %w", err)
	}
	cfg.MaxConns = 20
	cfg.MinConns = 2
	cfg.MaxConnLifetime = 30 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("datenbank nicht erreichbar: %w", err)
	}
	return pool, nil
}

// Migrate applies all pending migrations in order. Each runs in its own transaction
// and its checksum is recorded. A changed, already-applied file is an error.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	// Several panel instances may start at once; an advisory lock lets only one migrate.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	const lockID = 7264819350 // arbitrary constant owned by Sentinel Shield migrations
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, lockID); err != nil {
		return err
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, lockID)

	// All work below uses this one locked connection: waiting instances each hold a
	// connection, so asking the pool for another one could starve the lock holder.
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY,
		checksum text NOT NULL,
		applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		body, err := migrationFiles.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		checksum := hex.EncodeToString(sum[:])

		var existing string
		err = conn.QueryRow(ctx, `SELECT checksum FROM schema_migrations WHERE version = $1`, name).Scan(&existing)
		if err == nil {
			if existing != checksum {
				return fmt.Errorf("migration %s wurde nachträglich verändert", name)
			}
			continue
		}
		if err := applyOne(ctx, conn.Conn(), name, string(body), checksum); err != nil {
			return fmt.Errorf("migration %s: %w", name, err)
		}
	}
	return nil
}

func applyOne(ctx context.Context, conn *pgx.Conn, name, sql, checksum string) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, sql); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)`, name, checksum); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// MigrationNames lists the embedded migration files (for tests and diagnostics).
func MigrationNames() []string {
	entries, _ := fs.ReadDir(migrationFiles, "migrations")
	var out []string
	for _, e := range entries {
		out = append(out, strings.TrimSpace(e.Name()))
	}
	sort.Strings(out)
	return out
}
