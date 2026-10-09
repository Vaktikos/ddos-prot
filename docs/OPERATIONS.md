# Betrieb

## 1. Panel installieren (Docker Compose)

Voraussetzungen: Docker mit Compose v2, ein TLS-Zertifikat für die Panel-Domain, ein Host, der das Panel erreicht. Das Panel wird **nie** ohne TLS betrieben.

```bash
cd deploy/panel
cp .env.example .env
# Platzhalter ersetzen: Passwörter mit `openssl rand -base64 32` erzeugen.
mkdir -p secrets
cp /pfad/zum/zertifikat.pem secrets/panel-cert.pem
cp /pfad/zum/schluessel.pem secrets/panel-key.pem
openssl rand -base64 24 > secrets/admin-password.txt   # Passwort notieren, dann Datei sichern und löschen
chmod 600 .env secrets/*
docker compose up -d --build
docker compose logs -f panel
```

Das erste Konto wird beim ersten Start angelegt (`PANEL_ADMIN_EMAIL`, Passwort aus der Datei). Danach die Datei löschen; sie wird nicht mehr gelesen.

Das Panel legt beim ersten Start einen Ed25519-Signaturschlüssel in `/var/lib/sentinel-panel/signing.key` an (Volume `panelstate`). **Dieser Schlüssel muss gesichert werden** (siehe Abschnitt 5).

## 2. Agent installieren

Auf jedem Schutz-Node als root. Der Installer prüft Betriebssystem (Debian 11–13, Ubuntu 22.04/24.04), systemd, nftables und procfs. Er zeigt ein bestehendes Ruleset an und fragt nach, bevor er fortfährt. Er verändert nur die Tabelle `inet sentinel_shield`.

```bash
sudo scripts/install-agent.sh --binary ./bin/sentinel-agent --management-cidr 203.0.113.10/32 --dry-run
sudo scripts/install-agent.sh --binary ./bin/sentinel-agent --management-cidr 203.0.113.10/32
```

`--management-cidr` ist Pflicht und nennt die Netze, die der Agent niemals sperrt (typischerweise Ihr Administrationszugang). Mehrere Netze: Option wiederholen.

Danach:

1. `/etc/sentinel-shield/agent.json` prüfen: `panel_url`, `uplink_interfaces`.
2. Im Panel einen Node anlegen. Der Enrollment-Token wird **einmal** angezeigt.
3. `sudo /usr/local/bin/sentinel-agent enroll --config /etc/sentinel-shield/agent.json --token <TOKEN>`
4. `sudo systemctl enable --now sentinel-agent`
5. Im Panel prüfen: Status `online`, Sync `synced`, Modus `dry_run`.

Der Dienst wird vom Installer erst nach erfolgreicher Registrierung gestartet.

## 3. Modus schrittweise aktivieren

1. **Dry-Run** (Standard): Mindestens 48 Stunden beobachten. Vorschläge im Vorfallsbereich prüfen. Fehlalarme notieren.
2. **Mit Freigabe**: Maßnahmen erscheinen unter *Alarme & Freigaben* und werden erst nach Entscheidung wirksam. Unbeantwortete Freigaben laufen nach 15 min (Agent) bzw. 30 min (Panel) ab.
3. **Automatisch**: Nur für Ziele mit bestätigtem Verhalten aus Phase 2. Ratenlimits werden automatisch gesetzt; Quellsperren nur bis zum Limit der Sperrliste.

Modus pro Node im Panel unter *Nodes → Betriebsmodus*. Jede Änderung erzeugt eine neue Policy-Version und einen Audit-Eintrag.

## 4. Upgrade und Rollback

**Panel:** neues Image bauen und `docker compose up -d --build`. Migrationen laufen beim Start automatisch; jede Migration wird einmal in einer Transaktion angewendet und per Prüfsumme festgehalten. Vor jedem Upgrade ein Datenbank-Backup erstellen.

**Agent:** neues Binary per `install -m 0755 sentinel-agent /usr/local/bin/` ersetzen und `systemctl restart sentinel-agent`. Der Agent wendet danach die gecachte Policy an, bevor er das Panel kontaktiert. Ein Rollback ist das Zurücksetzen auf das alte Binary; das Format von `policy-cache.json` bleibt stabil.

**Policy:** *Nodes → Policy-Versionen → Zurücksetzen*. Die alte Version wird als **neue** Version mit neuer Nummer und neuer Signatur veröffentlicht. Versionsnummern laufen nie rückwärts.

**Protokollkompatibilität:** Der Heartbeat-Endpunkt lehnt unbekannte Felder ab. Agent und Panel sollten daher zusammen aktualisiert werden. Die Reihenfolge: zuerst Panel, dann Agents.

## 5. Backup und Wiederherstellung

Zu sichern:

| Was | Wo | Warum |
|---|---|---|
| PostgreSQL | Volume `pgdata` (`pg_dump -Fc`) | Zustand, Audit, Policy-Historie |
| Signaturschlüssel | Volume `panelstate`, Datei `signing.key` | Ohne ihn können Agents neue Policies nicht verifizieren. Bestehende Nodes würden alle neuen Policies ablehnen. |
| `.env` und `secrets/` | Verschlüsselter Tresor | Zugangsdaten und TLS-Schlüssel |

```bash
docker compose exec -T postgres pg_dump -U "$POSTGRES_USER" -Fc "$POSTGRES_DB" > sentinel-$(date +%F).dump
docker run --rm -v sentinel-shield_panelstate:/s alpine cat /s/signing.key > signing-$(date +%F).key   # verschlüsselt ablegen
```

Wiederherstellung: Stack stoppen, `pg_restore --clean -d …` in eine leere Datenbank, Signaturschlüssel zurückkopieren (Modus 0600), Stack starten. Danach im Panel prüfen, ob alle Nodes `online` sind und die letzte Policy-Version `synced` ist. Gehen Node-Zustände verloren, reicht eine Neuveröffentlichung je Node.

Wichtig: Ein **verlorener Signaturschlüssel** erfordert, alle Agents neu zu enrollen. Ein **Backup, das älter ist als die letzte Policy**, führt dazu, dass Agents eine neuere Version sehen, die das Panel nicht mehr kennt; in dem Fall die Policy neu veröffentlichen.

## 5a. Schlüsselrotation und Konten

- **Node-Schlüssel rotieren:** *Nodes → Node-Schlüssel rotieren* (Administrator). Der Agent tauscht den Schlüssel beim nächsten Heartbeat. Der alte Schlüssel ist danach ungültig.
- **MFA:** Jeder Benutzer richtet TOTP unter *Konto* ein. Recovery-Codes gibt es nicht; siehe `SECURITY.md`.
- **Policy-Version nach einem Datenbank-Restore:** Ein Agent übernimmt nur Versionen, die höher sind als seine aktive. Wurde das Panel aus einem älteren Backup wiederhergestellt, kann die nächste Version niedriger sein. Dann auf dem Node `systemctl stop sentinel-agent`, `/var/lib/sentinel-shield/policy-cache.json` entfernen, Agent starten und im Panel eine neue Policy veröffentlichen.

## 6. Notfallverfahren

| Lage | Maßnahme |
|---|---|
| Der Agent sperrt legitimen Traffic | Einzelne Sperre: *Regeln → Widerrufen*. Automatische Ratenlimits: Node auf **Dry-Run** stellen. Bestehende manuelle Sperren bleiben bis zum Widerruf aktiv. |
| Management-Zugang gesperrt | Über die Out-of-Band-Konsole zuerst `systemctl stop sentinel-agent`, dann `nft delete table inet sentinel_shield`. Die Reihenfolge ist wichtig: Ein laufender Agent würde die Tabelle beim nächsten Vorfall oder Neustart wieder anlegen. |
| Panel vollständig ausgefallen | Keine Aktion nötig. Agents schützen mit der letzten Policy weiter. Neue Freigaben sind nicht möglich, solange das Panel fehlt. |
| Node soll nicht mehr vertraut werden | Im Panel *Widerrufen*. Der Agent wird beim nächsten Heartbeat mit 403 abgewiesen. Danach `systemctl disable --now sentinel-agent`. |
| Alle Schutzregeln entfernen | `sudo systemctl disable --now sentinel-agent && sudo nft delete table inet sentinel_shield`. Der Agent entfernt seine Tabelle beim Stoppen **nicht**: Ein Absturz oder Neustart darf den Schutz nicht beenden. |

## 7. Logs, Überwachung und Rotation

- **Agent:** Logs gehen an das Journal (`journalctl -u sentinel-agent`). Rotation übernimmt journald (`SystemMaxUse` in `/etc/systemd/journald.conf`).
- **Panel:** JSON-Logs auf stdout. Der Docker-Logtreiber sollte mit `max-size` begrenzt werden.
- **Healthchecks:** Panel `/healthz` (Prozess), `/readyz` (Datenbank). Der Container-Healthcheck nutzt `/readyz`.
- **Alarme:** Offline-Nodes, bestätigte Angriffe, fehlgeschlagene Policy-Anwendungen und abgelehnte Signaturen erscheinen unter *Alarme & Freigaben*.
