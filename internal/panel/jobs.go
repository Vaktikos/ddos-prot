package panel

import (
	"context"
	"time"
)

// offlineAfter is how long a node may stay silent before it is marked offline.
// It is a multiple of the default heartbeat interval (30 s).
const offlineAfter = 2 * time.Minute

// RunJobs performs periodic maintenance until ctx is cancelled: offline detection,
// expiry of stale approvals and sessions, nonce cleanup and metric retention.
func (a *App) RunJobs(ctx context.Context) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	purge := time.NewTicker(time.Hour)
	defer purge.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			a.markOffline(ctx)
			a.expirePendingActions(ctx)
		case <-purge.C:
			a.purge(ctx)
		}
	}
}

func (a *App) markOffline(ctx context.Context) {
	rows, err := a.db.Query(ctx, `UPDATE nodes SET status = 'offline', updated_at = now()
		WHERE status IN ('online', 'degraded') AND last_heartbeat_at < now() - make_interval(secs => $1)
		RETURNING id::text, name`, offlineAfter.Seconds())
	if err != nil {
		a.log.Error("offline-prüfung fehlgeschlagen", "err", err)
		return
	}
	type down struct{ id, name string }
	var downs []down
	for rows.Next() {
		var d down
		if rows.Scan(&d.id, &d.name) == nil {
			downs = append(downs, d)
		}
	}
	rows.Close()
	for _, d := range downs {
		a.log.Warn("node offline", "node", d.name)
		_, _ = a.db.Exec(ctx, `INSERT INTO alerts (node_id, severity, source, title, message, dedupe_key)
			VALUES ($1::uuid, 'warning', 'node', $2, 'Keine Heartbeats mehr. Der lokale Schutz läuft mit der letzten Policy weiter.', $3)
			ON CONFLICT (dedupe_key) WHERE acknowledged_at IS NULL AND dedupe_key IS NOT NULL DO NOTHING`,
			d.id, "Node offline: "+d.name, "offline:"+d.id)
	}
}

// expirePendingActions times out approvals nobody answered. The agent does the same
// locally; this covers an agent that disappeared with requests still pending.
func (a *App) expirePendingActions(ctx context.Context) {
	_, _ = a.db.Exec(ctx, `UPDATE mitigation_actions SET status = 'expired', updated_at = now()
		WHERE status = 'pending_approval' AND created_at < now() - interval '30 minutes'`)
}

func (a *App) purge(ctx context.Context) {
	stmts := []string{
		`DELETE FROM agent_nonces WHERE expires_at < now()`,
		`DELETE FROM sessions WHERE expires_at < now() OR last_seen_at < now() - interval '30 minutes'`,
		`DELETE FROM node_metrics WHERE ts < now() - interval '30 days'`,
		`DELETE FROM target_metrics WHERE ts < now() - interval '30 days'`,
		`DELETE FROM agent_events WHERE received_at < now() - interval '90 days'`,
	}
	for _, s := range stmts {
		if _, err := a.db.Exec(ctx, s); err != nil {
			a.log.Error("wartungsjob fehlgeschlagen", "sql", s[:24], "err", err)
		}
	}
}
