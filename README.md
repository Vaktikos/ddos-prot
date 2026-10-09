# Sentinel Shield ai generated 

Eine DDoS-Schutzplattform für Hosting- und Datacenter-Betreiber: zentrales Webpanel, signierte Policies, Schutz-Agents auf den Servern, Erkennung und Mitigation über nftables.

**Stand: Kern plus XDP, Minecraft-Guard, Layer-7-Anbindung, Schlüsselrotation und Recovery-Codes.** Die Erkennung, die Mitigation, die Policy-Verteilung, das Panel und der Agent sind implementiert und getestet. Eine Liste dessen, was fehlt, steht unten und in `docs/TEST-REPORT.md`.

## Was funktioniert

- **Agent** (`cmd/agent`): misst Host und Ziele aus `/proc` und nftables-Zählern, erkennt Angriffe mit Schwellwerten, Baseline und Haltezeit, setzt Ratenlimits und zeitlich begrenzte Quellsperren über eine eigene nftables-Tabelle. Standardmodus `dry_run`.
- **Panel** (`cmd/panel`): Management-API mit Rollen (viewer, operator, admin), Argon2id, Sitzungen, CSRF-Schutz; Control Plane mit versionierten, Ed25519-signierten Policies und Rollback; Metrik-Ingest; Alarme, Freigabe-Workflow, Audit-Log.
- **Web-UI** (`web/`): React, TypeScript, Tailwind, Dark Theme. Übersicht mit Durchsatz, pps, Verwerfungen, Nodes, Zielen und Verlaufsdiagrammen aus gespeicherten Messwerten; Nodes mit Modus, Zielen, Regeln und Policy-Versionen; Vorfälle mit Zeitverlauf; Freigaben und Alarme; Audit.
- **Betrieb:** Docker-Compose-Stack für PostgreSQL und Panel; systemd-Unit für den Agent mit eingeschränkten Rechten; Installer für den Agent, der bestehende Firewall-Regeln nicht überschreibt.

## Zusätzlich umgesetzt

- **XDP-Frühfilter** (`internal/xdp`, `--xdp` im Installer): Sperrlisten (LPM-Tries) im Kernel, Sperren laufen kernelseitig ab, Management-/Vertrauens-/Panel-Adressen werden nie gesperrt. Auf einem echten Kernel getestet (`SS_XDP_INTEGRATION=1`).
- **Minecraft-Protokollprüfung** (`cmd/mcguard`, `docs/MINECRAFT.md`): Proxy mit Handshake-/Status-/Login-Prüfung, Limits je Quelle, automatische Sperren; der Agent liest dessen Statistik, erkennt `protocol_abuse` und spiegelt Sperren nach XDP.
- **Layer-7-Integration** (`internal/l7`): Der Agent liest das Reject-Log des Reverse Proxys (nginx-Vorlage `deploy/l7/`), meldet Ablehnungsrate und Top-Quellen, erkennt `http_flood` und sperrt (Profil-Option `l7_source_rps`) hartnäckige Quellen über XDP. Das Panel zeigt den Zustand je Node.
- **Signaturschlüssel**: austauschbare Signierer (Datei, externer Befehl, HashiCorp Vault Transit), Rotation mit vertrauenswürdigem Schlüsselsatz und zweistufigem Rollout (`docs/OPERATIONS.md`).
- **MFA-Recovery-Codes** (einmalig, gehasht gespeichert).
- **Einfache Einrichtung**: `scripts/install-panel.sh` (Panel, Compose) und `curl …/install.sh | sudo bash -s -- --token …` (Agent, mit SHA-256-Prüfung); das Panel liefert Binärdateien und Installer selbst aus.

## Was (noch) nicht umgesetzt oder nicht belegt ist

- Produktionsmessungen (Fehlalarmrate, Last des Panels, Wirkung unter realem Angriffsvolumen); siehe Testbericht
- Docker-Build, systemd-Betrieb und Installation auf einem echten Debian/Ubuntu-Host sind nicht ausgeführt worden
- Schutz gegen Sättigung der Leitung (nur beim Provider möglich), Layer-7-Regeln selbst (liegen im Reverse Proxy)
- XDP/Layer-7-Sperren setzen echte Client-Adressen voraus (hinter CDN/Load Balancer `real_ip` konfigurieren)
- Kein Vault-/KMS-Test gegen einen echten Dienst (Vault-Signierer nur gegen Testserver geprüft)

## Architektur in Kürze

```
Browser ──HTTPS──► Panel (API, Control Plane, Metrik-Ingest, Web-UI) ──► PostgreSQL 16
                      ▲  signierte Policy / Heartbeat (Ed25519, Nonce)
                      │
              Agent (systemd, nftables)  ──► Erkennung ──► Mitigation (Tabelle inet sentinel_shield)
```

Details: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Sicherheitsmodell und bekannte Lücken: [`docs/SECURITY.md`](docs/SECURITY.md). Grenzen der lokalen Mitigation und Anforderungen an vorgelagerte Filter: [`docs/MITIGATION-LIMITS.md`](docs/MITIGATION-LIMITS.md).

## Schnellstart

Panel (Docker Compose, TLS erforderlich): siehe [`docs/OPERATIONS.md`](docs/OPERATIONS.md), Abschnitt 1.

Agent auf einem Debian- oder Ubuntu-Node:

```bash
make build
sudo scripts/install-agent.sh --binary bin/sentinel-agent --management-cidr <IHR-VERWALTUNGSNETZ> --dry-run
sudo scripts/install-agent.sh --binary bin/sentinel-agent --management-cidr <IHR-VERWALTUNGSNETZ>
```

## Entwicklung

```bash
make test                                   # Vet, Format, Unit-Tests mit -race
SS_TEST_DSN="host=… dbname=sentinel_test …" make test-integration   # gegen PostgreSQL; leert das Schema der Testdatenbank
cd web && npm ci && npm run dev            # UI mit Proxy auf 127.0.0.1:8080
```

API-Spezifikation: [`docs/api/openapi.yaml`](docs/api/openapi.yaml).

## Verzeichnisse

| Pfad | Inhalt |
|---|---|
| `cmd/` | Einstiegspunkte: `agent`, `panel`, `healthcheck` |
| `internal/policy` | Policy-Modell, Validierung, Signatur |
| `internal/detect` | Erkennungsengine (Schwellen, Baseline, Haltezeit) |
| `internal/mitigate` | Entscheidung über Maßnahmen je Vorfall und Modus |
| `internal/nft` | nftables-Rendering und atomare Anwendung mit Rollback |
| `internal/agent` | Agent-Schleife, Outbox, signierter Panel-Client |
| `internal/panel` | Panel: Auth, RBAC, Policy-Kompilierung, Agent-API, Betriebs-API |
| `internal/store` | PostgreSQL-Pool und Migrationen |
| `internal/identity`, `internal/netaddr`, `internal/metrics` | Schlüssel und Signaturen, Adressen, procfs |
| `web/` | React-Frontend |
| `deploy/` | Docker Compose, Dockerfile, systemd-Unit, Beispielkonfigurationen |
| `scripts/` | Agent-Installer |
| `docs/` | Architektur, Sicherheit, Betrieb, Grenzen, Testbericht, OpenAPI |

## Lizenz

Noch nicht festgelegt.
