# Architektur

Sentinel Shield besteht aus zwei Binaries und einer Datenbank:

| Komponente | Läuft als | Aufgabe |
|---|---|---|
| **Panel** (`cmd/panel`) | Container (Docker Compose), hinter TLS | Management-API, Control Plane (Policy-Kompilierung, Signierung, Versionierung), Agent-API, Metrik-Ingest, Alarmierung, Web-UI |
| **Agent** (`cmd/agent`) | nativer systemd-Dienst auf jedem Schutz-Node | Messung, Erkennung, Mitigation über nftables, signierter Kanal zum Panel |
| **PostgreSQL 16** | Container im internen Netz | Zustand, Zeitreihen, Audit-Log, Policy-Versionen |

Redis wurde bewusst **nicht** eingeführt: Nonce-Schutz, Sitzungen und Metriken liegen in PostgreSQL mit Zeitindizes. Ein zusätzlicher Dienst hätte keinen Nutzen, den die Datenbank nicht auch erfüllt.

## Wichtige Entscheidungen

**Go für Panel und Agent.** Ein statisches Binary ohne Laufzeitabhängigkeiten passt zu netzwerknahen Diensten auf fremden Hosts. Die Standardbibliothek liefert TLS, HTTP und Ed25519 ohne externe Krypto-Stacks.

**nftables zuerst, eBPF/XDP später.** nftables ist auf allen unterstützten Distributionen vorhanden, lässt sich atomar laden (`nft -f` ist eine Netlink-Transaktion), prüfen (`nft -c`) und mit Zählern und Timeouts betreiben. XDP wäre schneller, erfordert aber Treiberunterstützung, Kernel-Versionen und eine eigene Fehlerbehandlung. Das ist ein späterer Schritt, kein Ersatz für die jetzige Lösung. **Stand heute ist eBPF/XDP nicht implementiert.**

**Pull statt Push.** Der Agent holt die Policy per signiertem Request. Das vermeidet eingehende Verbindungen zu Nodes und macht den Agent unabhängig von der Erreichbarkeit des Panels für den laufenden Betrieb.

**Signierte Policies.** Das Panel signiert den exakten kanonischen JSON-Body mit Ed25519. Der Agent pinnt den öffentlichen Panel-Schlüssel beim Enrollment und akzeptiert nur Envelopes, deren Signatur, SHA-256 und Version übereinstimmen. Eine manipulierte Policy wird verworfen, die letzte gültige bleibt aktiv (durch Test belegt).

**Agent-Autonomie.** Der Agent speichert die letzte verifizierte Policy und wendet sie beim Start an, bevor er das Panel erreicht. Erkennung und Mitigation laufen weiter, wenn das Panel ausfällt. Ein Ausfall deaktiviert nie automatisch den Schutz. Im Freigabe-Modus entstehen während eines Ausfalls keine neuen Maßnahmen, weil keine Freigabe eintreffen kann; bestehende Regeln bleiben aktiv.

**Standardmodus `dry_run`.** Neue Nodes erkennen Angriffe und protokollieren Vorschläge, verändern aber keine Firewall-Regel außer ausdrücklich freigegebenen Sperren. Umschalten auf `approval` oder `auto` ist ein bewusster, auditierter Schritt.

**Maßnahmen gehören zu einem Vorfall.** Ratenlimits existieren im Ruleset nur, solange der zugehörige Vorfall bestätigt ist (Kommentar `comment "<Vorfall>"` in jeder Regel). Das Profil legt nur die erlaubten Parameter fest.

**Zwei-Stufen-Erkennung.** Absolute Schwellen (pps, SYN/s, UDP/s, ICMP/s) werden mit einer adaptiven Baseline (EWMA über ruhige Phasen, Aufwärmphase von 30 Samples, Ausreißer werden auf das 4-Fache geklippt) kombiniert. Ein Vorfall wird nur bestätigt, wenn das Fenster zu mindestens 80 % getroffen wurde. Einzelne Ausreißer lösen daher keine Sperre aus.

## Datenfluss

```
Browser ──HTTPS, Cookie, CSRF──► Panel API ──► PostgreSQL
                                     │
Agent ──signiert (Ed25519, Nonce, Zeitstempel)──► /agent/v1/*
   │  heartbeat: Host- und Ziel-Metriken, Ereignis-Outbox, Health
   │  policy:    signierter Envelope (Body, SHA-256, Signatur)
   ▼
nftables Tabelle inet sentinel_shield (Zähler → Erkennung; Sets → Sperren; Meter → Ratenlimits)
```

Bei jedem Heartbeat wird eine Policy-Version gemeldet. Weicht sie von der gewünschten ab, lädt der Agent die neue Version, prüft sie und meldet die Anwendung im nächsten Heartbeat zurück. Die Übernahme wird sofort bestätigt, damit der Sync-Status nicht hinter dem Ist-Zustand zurückbleibt.

Ereignisse (Vorfälle, Maßnahmen, Alarme, Policy-Status) bleiben im Agent-Outbox, bis das Panel den Heartbeat bestätigt hat. Das Panel verarbeitet jedes Ereignis genau einmal (Primärschlüssel `(node_id, event_id)`), auch bei Wiederholungen. Pro Heartbeat werden höchstens 300 Ereignisse übertragen; ein Rückstau nach einem Ausfall wird über mehrere Heartbeats abgebaut.

## Datenmodell

Migrationen liegen in `internal/store/migrations/` und werden beim Start eingespielt; eine nachträglich veränderte Migration wird über eine Prüfsumme erkannt. Zeitreihen (`node_metrics`, `target_metrics`) sind über `(Entität, ts)` indiziert, Ereignisse und Audit-Log über `ts`. Retention: Metriken und Ereignisse 30 bzw. 90 Tage, Nonces und abgelaufene Sitzungen werden stündlich entfernt.

## Fehlerszenarien

| Szenario | Verhalten |
|---|---|
| Panel nicht erreichbar | Agent schützt mit letzter verifizierter Policy weiter; Heartbeats werden wiederholt, Ereignisse bleiben im Outbox |
| Agent-Neustart | Gecachte Policy wird vor dem Panel-Kontakt angewendet; kernelseitige Sperren bleiben bestehen, Ratenregeln werden nach erneuter Erkennung neu gesetzt |
| Manipulierte Policy | Verworfen, Fehler wird im Heartbeat gemeldet, Alarm im Panel |
| Ruleset wird vom Kernel abgelehnt | Vorheriger Stand wird aus dem Kernel gelesen und wiederhergestellt; Fehler gemeldet |
| Node-Ausfall | Nach 2 min ohne Heartbeat `offline`, Alarm einmalig (Dedupe) |
| Replay eines Heartbeats | Nonce bereits verbraucht, Antwort 401 |
| Sperre würde Management-Netz treffen | Policy wird im Panel abgelehnt, Agent lehnt sie ebenfalls ab |
| Gleichzeitige Änderungen | Sperre des Node-Datensatzes vor jeder Schreiboperation; parallele Änderungen ergeben lückenlose Versionen (durch Test belegt, nach Behebung eines Deadlocks) |
