# Minecraft-Guard (`sentinel-mcguard`)

Ein Proxy für Minecraft **Java Edition**, der vor dem Spielserver läuft. Er liest bei jeder Verbindung den Handshake (VarInt-Länge, Paket-ID, Protokollversion, Host, Port, nächster Zustand) und leitet nur gültige Verbindungen weiter.

## Was er prüft

- Handshake: Länge, Paket-ID, Feldgrenzen, Zustand (Status/Login), optional erlaubte Hostnamen (`allowed_hosts`). Zeitlimit für den Handshake.
- Status: Ping-Anfragen je Quelle und Minute begrenzt.
- Login: nur Weiterleitung nach gültigem Handshake; danach Leerlaufgrenze.
- Je Quelle: parallele Verbindungen, neue Verbindungen pro Sekunde (mit Burst), globale Obergrenze.
- Ungültige Handshakes zählen; ab `ban_after_invalid` innerhalb `ban_window_seconds` wird die Quelle für `ban_seconds` gesperrt. `allow_cidrs` sind nie sperrbar.
- Optional PROXY-Protokoll zum Server (`proxy_protocol`), damit der Server die echte Quelladresse sieht (Server muss es unterstützen).

## Einrichtung

```bash
sudo install -m 0755 sentinel-mcguard /usr/local/bin/
sudo install -d /etc/sentinel-shield
sudo cp deploy/minecraft/mcguard.example.json /etc/sentinel-shield/mcguard.json   # anpassen
sentinel-mcguard --check --config /etc/sentinel-shield/mcguard.json
sudo cp deploy/minecraft/sentinel-mcguard.service /etc/systemd/system/ && sudo systemctl enable --now sentinel-mcguard
```

Der Spielserver lauscht dann nur auf `127.0.0.1:25566` (Port in der Konfiguration), der Guard auf dem öffentlichen Port. Statistik: `http://127.0.0.1:9199/stats` (nur Loopback).

## Anbindung an Agent und Panel

Installer: `--mc-guard mc,9199,192.0.2.10/32` (oder `minecraft_guards` in `agent.json`). Im Profil `protocol_abuse_pps` setzen (Vorlage `deploy/profiles/minecraft-java.json`). Der Agent meldet den Guard-Zustand an das Panel (Node-Seite), eröffnet bei Überschreitung einen Vorfall `protocol_abuse` und spiegelt aktive Guard-Sperren in den XDP-Filter (nicht im Dry-Run; nie Management-/Vertrauens-/Panel-/Schutzadressen).

## Grenzen

- Bedrock (UDP) wird nicht geprüft. Verschlüsselte Spielpakete werden nicht inspiziert.
- Der Guard ist ein Proxy: er verbraucht selbst CPU und Verbindungen; er hilft nicht, wenn die Leitung gesättigt ist.
- Hinter einem NAT teilen sich Spieler eine Adresse; `max_per_source` und `new_conn_per_second` entsprechend wählen.
- Geprüft durch Unit-, Fuzz- und Parallelitätstests (viele gleichzeitige Spieler) mit simuliertem Backend (siehe `TEST-REPORT.md`); nicht gegen einen echten Minecraft-Server und nicht unter Produktionslast.
