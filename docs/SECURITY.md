# Sicherheitsmodell

## Vertrauensgrenzen

1. **Browser → Panel:** Sitzungs-Cookie (HttpOnly, Secure, SameSite=Strict), CSRF-Token im Header, Origin-Prüfung.
2. **Agent → Panel:** Ed25519-Signatur über Methode, Pfad, Zeitstempel, Nonce und SHA-256 des Bodys.
3. **Panel → Agent:** Policies sind signiert. Der Agent vertraut dem Transport nicht, sondern nur der Signatur gegen den beim Enrollment gepinnten Schlüssel.
4. **Agent → Kernel:** Der Agent erzeugt keine Shell-Befehle aus Daten des Netzwerks. Jeder Wert wird als `netip.Prefix`, Port oder Ganzzahl validiert, bevor er ins nft-Skript geschrieben wird. Tabellennamen und Vorfalls-IDs werden auf erlaubte Zeichen geprüft.

## Umgesetzt und getestet

| Kontrolle | Umsetzung | Nachweis |
|---|---|---|
| Passwortspeicherung | Argon2id (64 MiB, t=3, p=2), Salt pro Hash, konstante Zeitvergleiche, Dummy-Hash bei unbekanntem Benutzer | `TestEndToEnd` (Fehlversuch), `auth.go` |
| Kontosperre | 5 Fehlversuche → 15 min gesperrt; Anmeldung pro IP 10/min | Code-Pfad in `login`; Rate-Limit-Test fehlt (siehe Lücken) |
| Sitzungen | Zufällige 256-Bit-Token, nur SHA-256 gespeichert, 12 h absolut, 30 min Leerlauf | `TestEndToEnd` (Login, Logout-Pfad, Berechtigungen) |
| Rollen | viewer < operator < admin, Prüfung in jedem Handler über `withSession` | `TestEndToEnd` (viewer darf nicht schreiben, kein Audit-Zugriff) |
| CSRF | Header `X-CSRF-Token` konstant-zeitig verglichen, Origin muss exakt passen | `TestEndToEnd` (fehlendes Token, fremder Origin) |
| Enrollment | Einmal-Token, 256 Bit, nur Hash gespeichert, 24 h gültig, atomar verbraucht | `TestEndToEnd` (zweite Verwendung scheitert) |
| Agent-Identität | Ed25519 pro Node, Schlüsseldatei 0600, Start verweigert bei offenen Rechten | `identity_test.go` |
| Replay-Schutz | Nonce pro Node in PostgreSQL (Primärschlüssel), Zeitfenster ±60 s | `TestEndToEnd` (zweiter identischer Request → 401) |
| Manipulation | Body-Hash in der Signatur; veränderter Body → 401 | `TestEndToEnd`, `identity_test.go` |
| Policy-Integrität | Signatur, SHA-256 und Version werden vor jeder Übernahme geprüft; unbekannte Felder werden abgelehnt | `policy_test.go`, `TestTamperedPolicyIsRejectedAndPreviousKept` |
| Management-Schutz | Sperren und Policies, die Management-Netze treffen, werden im Panel **und** im Agent abgelehnt; Agent verlangt Management-Netze in der Konfiguration | `TestRenderRefusesManagementBlock`, `TestEndToEnd` (422) |
| Eingabevalidierung | Strikte JSON-Dekodierung (unbekannte Felder abgelehnt), Größenlimits (1 MiB, Heartbeat 4 MiB), Längen- und Wertebereiche | Tests in `policy_test.go`, `netaddr_test.go` |
| SQL-Injection | Alle Werte parametrisiert; die einzige interpolierte Eingabe (`node_id`-Filter) wird auf UUID-Format geprüft | Code-Review, `sanitizeUUID` |
| XSS | React escaped Ausgaben; keine `dangerouslySetInnerHTML`; CSP `default-src 'self'` | Build und Header |
| Transportsicherheit | TLS 1.2+ im Panel (`PANEL_TLS_CERT`), Agent verweigert `http://` außer localhost | `TestPanelClientRequiresHTTPSExceptLoopback` |
| Audit | Jede schreibende Aktion und Anmeldefehler landen im `audit_log` mit IP | `TestEndToEnd` (Einträge vorhanden) |
| Privilegien des Agents | systemd: nur `CAP_NET_ADMIN`, `ProtectSystem=strict`, `RestrictAddressFamilies`, `MemoryDenyWriteExecute` | `deploy/agent/sentinel-agent.service` (nicht auf einem Host mit systemd geprüft, siehe Lücken) |
| Container | Distroless-Image, Nicht-Root, Read-only-Dateisystem, `cap_drop: ALL`, `no-new-privileges` | `deploy/panel/docker-compose.yml` (nicht gebaut, siehe Lücken) |
| Sichere Standardkonfiguration | Modus `dry_run`, Sperren nur befristet (max. 30 Tage), Cookie `Secure` erzwungen bei https | `config.go`, `policy.MaxBlockDays` |

## Bekannte Lücken (ehrlich benannt)

- **MFA ist nicht implementiert.** Das Konzept sieht TOTP vor; die Datenbank hat dafür noch keine Spalte. Bis dahin sollte der Zugriff nur über ein VPN oder einen SSO-Proxy mit MFA erfolgen.
- **Kein Rate-Limit-Test** für die Anmeldung. Der Limiter existiert, ist aber nur über den Code geprüft.
- **Signaturschlüssel des Panels** liegt als Datei (0600) auf dem Panel-Host. Ein HSM oder KMS ist vorgesehen, aber nicht umgesetzt. Ein Verlust des Schlüssels ist kritisch (siehe `OPERATIONS.md`, Backup).
- **Kein Schlüsselwechsel für Nodes.** Ein kompromittierter Agent wird durch Widerruf gesperrt, nicht durch Rotation des Schlüssels. Neu-Enrollment erfordert einen neuen Node.
- **Kein Proxy-Vertrauen.** Das Panel nutzt nur die TCP-Gegenstelle als Client-IP. Hinter einem Reverse Proxy sind Rate-Limits daher pro Proxy-IP wirksam, nicht pro Client.
- **Panel-Heartbeat ist nicht gegen Schlüsselklau durch lokale root-Angreifer geschützt.** Wer root auf dem Node hat, kann den Agent übernehmen und Sperren setzen. Das ist ein Grundproblem jedes Host-Agents; die Schadensbegrenzung liegt in den Management-Netzen und Limits, nicht in der Identität.
