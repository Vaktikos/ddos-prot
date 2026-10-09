# Testbericht Phase 1

Stand: 2026-10-09. Umgebung: Ubuntu 24.04.5 in einer VM (Kernel 6.18), Go 1.24.7, nftables 1.0.9, PostgreSQL 16.15, Node 22.22. Alle Angriffsmessungen liefen **ausschließlich auf dem Loopback-Interface** gegen eine Testadresse (`192.0.2.10`), die nur auf diesem Host existiert. Es wurden keine fremden Ziele belastet.

## 1. Automatisierte Tests

| Paket | Tests | Inhalt | Ergebnis |
|---|---|---|---|
| `internal/netaddr` | 3 | Adressnormalisierung, Mindest-Präfixlängen, Familienüberlappung | bestanden |
| `internal/policy` | 4 | Validierung (12 Ablehnungsfälle inkl. Management- und Trusted-Konflikt), Signatur, Manipulation | bestanden |
| `internal/detect` | 12 | synthetische Messreihen: Ruhe, SYN-Flood, Kurzimpuls, adaptive Anomalie, Verkehrsspitze, Warm-up, IPv6-ICMP, Ziel-Unabhängigkeit, Eingabevalidierung, Ausschluss von Zustandsexplosion | bestanden |
| `internal/mitigate` | 7 | Stufen, Modi (dry_run/approval/auto), volle Sperrliste, Freigabe-Timeout, Entfernen je Vorfall | bestanden |
| `internal/nft` | 10 | deterministisches Rendering, Accept vor Drop, abgelaufene Sperren entfallen, Ablehnung manipulierter Namen, Kernel-Parser (`nft -c`), Zählerparser, Integration mit Rollback | bestanden |
| `internal/metrics` | 5 | /proc-Parser, CPU-Berechnung, Live-Lesen | bestanden |
| `internal/identity` | 6 | Signatur, falscher Schlüssel, Zeitfenster, fehlende Header, Replay-Speicher, Schlüsselrechte | bestanden |
| `internal/agent` | 10 | Dry-Run, Auto-Modus mit Entfernung nach Vorfall, Freigabe, **Panel-Ausfall mit Cache-Start**, **manipulierte Policy**, Kernel-Fehler, Outbox-Limit, HTTPS-Pflicht, Management-Pflicht | bestanden |
| `internal/store` | 1 | Migrationen auf echtem PostgreSQL (inkl. 0002), idempotenter zweiter Lauf | bestanden (mit `SS_TEST_DSN`) |
| `internal/panel` | 5 | TOTP-Testvektoren (RFC 6238), Replay-Schutz, Verschlüsselung des Geheimnisses, MFA-Login gegen PostgreSQL | **End-to-End** gegen PostgreSQL: Enrollment, Einmal-Token, signierte Heartbeats, Replay, Manipulation, Angriff und Schutz, Freigabe-Workflow, Sperren, Management-Schutz, Rollback, RBAC, CSRF, Origin, Login-Fehler, Dashboard, Audit, Widerruf. **Gleichzeitige Änderungen:** 12 parallele Schreibvorgänge am selben Node, lückenlose Versionen | bestanden (mit `SS_TEST_DSN`) |

Der Lauf mit `-race` war sauber. Die Gleichzeitigkeitsprüfung hat einen **echten Deadlock** zwischen parallelen Policy-Änderungen aufgedeckt (PostgreSQL `40P01`). Behoben durch Sperren des Node-Datensatzes als erste Schreiboperation jeder Transaktion. Der Test läuft seitdem dreimal hintereinander fehlerfrei und ohne fehlgeschlagene Anfragen.

Zusätzlich: Kernel-Integrationstest der nftables-Tabelle (`SS_NFT_INTEGRATION=1`, root) lädt das Ruleset, liest Zähler, weist ein fehlerhaftes Skript zurück und belegt, dass die vorherige Tabelle erhalten bleibt.

## 2. Messungen am lebenden System

Ablauf: echtes `sentinel-panel` und echtes `sentinel-agent` (Enrollment über das Netz, Policy-Abruf, Heartbeats), echter nftables-Kernel, echte `/proc`-Werte. Angriff: Python-Skript mit nicht blockierenden Verbindungsversuchen auf `192.0.2.10:443` über das Loopback-Interface.

| Messung | Ergebnis | Bedingungen |
|---|---|---|
| Erste Erkennung nach Floodbeginn | 0,58 s | Lauf 1, Schwelle 500 SYN/s, Haltezeit 3 s |
| Alarm „bestätigter Angriff“ im Panel nach Floodbeginn | 3,9 s | Lauf 2; Haltezeit 3 s, Sofort-Heartbeat (Mindestabstand 5 s) |
| Alarm im Panel vor dem Sofort-Heartbeat | 5,6 s | Lauf 1 (Heartbeat-Intervall 5 s); Anlass für die Änderung |
| SYN-Rate während des Floods | ca. 100–124 k SYN/s aus einem Prozess | nur Loopback, Ausgangslast |
| Kernel-Zähler `dyn_drop4` (verworfen durch Quellsperre) | 1,36 M Pakete in 15 s | Quelle war die Testadresse selbst |
| Ratenregeln nach Vorfallende | entfernt (0 `meter ss_*`) | Vorfall schloss nach 5 s Ruhe |
| Quellsperren nach Ablauf | 0 Elemente nach 70 s | Timeout `auto_block_seconds = 60` |
| CPU des Agents während 15 s Flood | 0,2 % eines Kerns | Lauf 2 |
| CPU des Agents während 10 s Flood (erster Lauf) | 2 % eines Kerns | Lauf 1, schließt erste Regelanwendung ein |
| CPU des Agents im Leerlauf (20 s) | 0,15 % | nach Neustart |
| RSS des Agents | 9,7 MB Leerlauf, 12,8 MB unter Flood | |
| Neustart des Agents | gecachte Policy v3 in ca. 50 ms angewendet, **vor** dem Panel-Kontakt | `source: cache` im Log |

Die Erkennungsverzögerung bis zum Alarm hängt von der Haltezeit ab (`confirm_seconds`). Der Anteil, den der Agent verantwortet, liegt im Sub-Sekunden-Bereich; den Rest bestimmt die gewählte Haltezeit.

## 3. Akzeptanzkriterien

Die Ziele stehen hier, damit sie überprüfbar bleiben. Der Status zeigt, was gemessen wurde.

| Kriterium | Zielwert | Status |
|---|---|---|
| Erkennungsverzögerung (erster Treffer) | ≤ 1 s bei Flood über Schwelle | **gemessen**: 0,58 s (eine Umgebung, eine Angriffsart) |
| Alarmverzögerung bei bestätigtem Angriff | ≤ haltezeit + 2 s | **gemessen**: 3,9 s bei Haltezeit 3 s |
| Agent-CPU im Leerlauf | < 1 % | **gemessen**: 0,15 % (eine Messung über 20 s) |
| Agent-CPU unter Flood | < 5 % eines Kerns | **gemessen**: 0,2 % bzw. 2 % (zwei Läufe) |
| Speicher des Agents | < 50 MB | **gemessen**: 12,8 MB unter Flood (einmalig) |
| Fehlalarmrate | 0 bestätigte Vorfälle bei ruhigem Traffic über 24 h | **nicht gemessen**: kein Produktionstraffic verfügbar |
| Wiederherstellung nach Agent-Neustart | Schutz ohne Panel-Verbindung | **gemessen**: Neustart mit gecachter Policy, Panel nicht erreichbar in Unit-Tests |
| Wiederherstellung nach Panel-Ausfall | Schutz läuft weiter, Sync nach Rückkehr | **durch Test belegt** (Agent-Test mit abgeschaltetem Panel); Rückkehr-Sync im E2E-Test |
| Replay-Schutz | Zweiter identischer Request abgelehnt | **durch Test belegt** |
| Gleichzeitige Änderungen | lückenlose, eindeutige Versionen | **durch Test belegt** (12 parallele Änderungen) |
| Hohe Ereignisraten | begrenzter Speicher, kein Verlust bestätigter Ereignisse | **teilweise**: Outbox-Limit 5000 getestet; Durchsatz des Panels unter Last **nicht gemessen** |
| Mitigation-Wirkung auf legitimen Traffic | keine Beeinträchtigung | **nicht gemessen** |

## 4. Nicht geprüft (bewusste Lücken)

- **Installer und systemd-Unit** wurden nicht auf einem Debian- oder Ubuntu-Host mit laufendem systemd ausgeführt. Die Shell-Syntax ist geprüft, `shellcheck` war nicht verfügbar.
- **Docker-Image und Compose-Stack** wurden nicht gebaut; auf dem Testhost gibt es keinen Docker-Daemon.
- **Web-UI** ist nur durch den TypeScript-Compiler und den Vite-Build geprüft, nicht im Browser.
- **Mehrere Nodes und Standorte** wurden nicht im Betrieb getestet. Die Datenstrukturen sind dafür angelegt.
- **Lange Laufzeit** (Tage) und **Retention-Jobs** sind nicht gemessen; die Jobs laufen stündlich, ihre Ausführung ist nicht beobachtet.
- **Angriffe mit realem Volumen** und Netzwerkangriffe über echte Leitungen wurden nicht gemessen. Die Messungen sind Laborwerte.

## 5. Reproduktion

```bash
make test                                              # Unit-Tests mit Race-Detector
SS_TEST_DSN="host=127.0.0.1 port=5432 user=postgres dbname=sentinel_test sslmode=disable" make test-integration
sudo make test-nft                                     # nur auf einem Wegwerf-Host
cd web && npm ci && npm run build
```
