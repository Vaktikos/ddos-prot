# Was der Agent leisten kann und was nicht

Ein Agent auf dem Zielserver kann nur Pakete verwerfen, die **bei ihm ankommen**. Wenn der physische Uplink bereits durch eingehenden Angriffs-Traffic gesättigt ist, bevor er den Server erreicht, kann kein Agent auf dem Server die Bandbreite zurückholen. Diese Grenze gilt für jede lokale Lösung und ist nicht durch Software behebbar.

## Übersicht

| Angriffsklasse | Lokal im Agent | Mit vorgelagertem Filter / Provider nötig |
|---|---|---|
| UDP-Flood, Reflection mit kleinem Volumen | Erkennung; quellbezogene Ratenbegrenzung (`udp_rate_per_source`) | Bei gesättigter Leitung: Scrubbing beim Provider |
| TCP-SYN-Flood auf Dienste | Erkennung; SYN-Ratenlimit pro Quelle; temporäre Quellsperre im Kernel | Bei Volumen über der Leitungskapazität: Scrubbing / Anycast |
| ICMP-Flood | Erkennung (Zähler und Schwelle), **keine** automatische Mitigation | Upstream-Filter für ICMP empfohlen |
| Verbindungserschöpfung | Host-Ebene: Auslastung der conntrack-Tabelle wird überwacht, ab 80 % meldet der Node `degraded`. Pro Ziel nur über SYN-Zählung und `conn_pps` sichtbar | conntrack-Limits oder Proxy/LB mit Verbindungslimits |
| Fragmentierungsangriffe | Erkennung (`frag_pps`, Zähler für IPv4-Fragmente und IPv6-Fragment-Header); bei Vorfall optional Verwerfen (`drop_fragments`) | Upstream-Normalisierung bei hohem Volumen |
| Ungültige TCP-Flags (Null, Xmas, SYN+FIN, SYN+RST, FIN ohne ACK) | Erkennung (`invalid_pps`); bei Vorfall optional Verwerfen (`drop_invalid`). Weitere Protokollanomalien sind nicht abgedeckt | Vorgelagerte Normalisierung |
| Volumetrisch von wenigen Quellen | XDP-Sperre starker Quellen (`xdp_source_pps`), kernelseitiges Ablaufen. Bei gesättigter Leitung wirkungslos; verteilte Angriffe mit vielen schwachen Quellen werden nicht erfasst | Scrubbing |
| Angriffe auf einzelne Ports | Zähler je Dienst (Pakete, SYN); Ratenlimit je Port | Port-Filter vor dem Server |
| Layer 7 (HTTP-Floods, Request-Muster) | Der Reverse Proxy (nginx-Vorlage `deploy/l7/`) lehnt ab; der Agent liest das Reject-Log, erkennt `http_flood` (`http_reject_rps`) und sperrt Quellen per XDP (`l7_source_rps`). **Keine eigene Request-Analyse**, keine Regeln im Proxy durch den Agent | Reverse Proxy/WAF mit Rate-Limits; hinter CDN `real_ip` setzen |
| Verbindungsflut auf einen Minecraft-Port | Erkannt über neue Verbindungen je Dienstport (`conn_pps`, SYN-Zähler, ohne SYN-Verhältnis). Mitigation über das SYN-Ratenlimit, das alle TCP-Dienste des Ziels betrifft | Bei Volumen über der Leitung: Scrubbing |
| Minecraft-Handshake, Status-Pings (Java) | `sentinel-mcguard` prüft Handshake, Status und Login, begrenzt Pings und sperrt Quellen; Agent erkennt `protocol_abuse` und spiegelt Sperren nach XDP. Der Guard ist ein Proxy: der Server sieht die Quelladresse nur mit PROXY-Protokoll. Bei Volumen über der Leitung wirkungslos. Keine Prüfung verschlüsselter Spielpakete | Scrubbing bei Volumen |
| Minecraft-Bedrock (UDP) | Wie generisches UDP; keine Verbindungsrate, weil UDP keine Verbindungen kennt | Upstream-Filter |

## Ratenlimits und Sperren

- **SYN-Ratenlimit** (`syn_rate_per_source`): begrenzt neue TCP-Verbindungsversuche pro Quelladresse auf den Diensten eines Ziels. Legitime Clients erzeugen selten mehr als wenige SYN/s. Der Wert muss pro Dienst gewählt werden: Ein Minecraft-Server mit vielen Spielern hinter einem NAT sieht von einer Adresse mehrere Verbindungen gleichzeitig; hier ist ein höherer Wert nötig.
- **Temporäre Quellsperre** (`auto_block_seconds`): Quellen, die das Limit überschreiten, landen im Kernel-Set `dyn4`/`dyn6` mit eigenem Timeout. Die Sperre endet ohne Zutun des Agents. Vertrauenswürdige und Management-Netze werden vor allen Sperr-Regeln akzeptiert.
- **Hinweis zu NAT:** Hinter einem NAT teilen sich viele Nutzer eine Quelladresse. Ein Ratenlimit pro Quelle kann dort legitime Nutzer treffen. Deshalb ist die Mitigation für NAT-lastige Dienste (Minecraft, Spiele) standardmäßig im Freigabe-Modus zu betreiben und das Limit bewusst zu setzen.

## Was ausdrücklich nicht versprochen wird

- Keine Aussage über Schutzwirkung gegen konkrete Angriffe ohne Messung in der jeweiligen Umgebung. Die Messungen, die vorliegen, sind in `TEST-REPORT.md` aufgeführt.
- Keine Erkennung von Angriffen, die unterhalb der Zählergranularität liegen (ein Zähler je Ziel und Dienst, Sekundenauflösung).
- Keine Garantie, dass die Erkennungsverzögerung unter realem Angriffsvolumen die gemessenen Werte einhält.
