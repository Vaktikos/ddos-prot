package store

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// scratchDB creates an empty database next to the one in SS_TEST_DSN, so the test does
// not interfere with other packages that use the shared test database in parallel.
func scratchDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("SS_TEST_DSN")
	if dsn == "" {
		t.Skip("SS_TEST_DSN nicht gesetzt")
	}
	ctx := context.Background()
	admin, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("ss_mig_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg, _ := pgxpool.ParseConfig(dsn)
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(ctx, "DROP DATABASE "+name+" WITH (FORCE)")
		admin.Close()
	})
	return pool
}

func TestMigrateIntegration(t *testing.T) {
	pool := scratchDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("erster Lauf: %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("zweiter Lauf muss idempotent sein: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil || n != len(MigrationNames()) {
		t.Fatalf("schema_migrations = %d, erwartet %d (%v)", n, len(MigrationNames()), err)
	}
	var tables int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('users','sessions','nodes','rules','policy_versions','incidents','alerts','audit_log')`).Scan(&tables); err != nil || tables != 8 {
		t.Fatalf("erwartete Kerntabellen fehlen: %d %v", tables, err)
	}
}

// Several panel instances starting together must not break each other.
func TestMigrateConcurrentStarts(t *testing.T) {
	pool := scratchDB(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- Migrate(ctx, pool)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("paralleler Start: %v", err)
		}
	}
}
