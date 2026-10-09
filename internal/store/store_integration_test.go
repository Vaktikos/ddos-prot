package store

import (
	"context"
	"os"
	"testing"
)

// TestMigrateIntegration needs a PostgreSQL database in SS_TEST_DSN. It is skipped otherwise.
func TestMigrateIntegration(t *testing.T) {
	dsn := os.Getenv("SS_TEST_DSN")
	if dsn == "" {
		t.Skip("SS_TEST_DSN nicht gesetzt")
	}
	ctx := context.Background()
	pool, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("erster Lauf: %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("zweiter Lauf muss idempotent sein: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil || n < 1 {
		t.Fatalf("schema_migrations leer: %d %v", n, err)
	}
	var tables int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('users','sessions','nodes','rules','policy_versions','incidents','alerts','audit_log')`).Scan(&tables); err != nil || tables != 8 {
		t.Fatalf("erwartete Kerntabellen fehlen: %d %v", tables, err)
	}
}
