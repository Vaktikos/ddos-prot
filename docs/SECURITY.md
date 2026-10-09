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
| Kontosperre | 5 Fehlversuche → 15 min gesperrt; Anmeldung pro IP 10/min | `TestLoginAccountLockout`, `TestLoginIsRateLimitedPerClient` |
| MFA (TOTP, RFC 6238) | Optional pro Konto; Geheimnis AES-GCM-verschlüsselt; Codes nur einmal gültig (`totp_last_step`); falscher Code zählt als Fehlversuch | `TestTOTPRFC6238Vector`, `TestTOTPRejectsReplayAndOutOfWindow`, `TestMFALoginFlow` |
| Sitzungen | Zufällige 256-Bit-Token, nur SHA-256 gespeichert, 12 h absolut, 30 min Leerlauf | `TestEndToEnd` (Login, Logout-Pfad, Berechtigungen) |
| Rollen | viewer < operator < admin, Prüfung in jedem Handler über `withSession` | `TestEndToEnd` (viewer darf nicht schreiben, kein Audit-Zugriff) |
| CSRF | Header `X-CSRF-Token` konstant-zeitig verglichen, Origin muss exakt passen | `TestEndToEnd` (fehlendes Token, fremder Origin) |
| Enrollment | Einmal-Token, 256 Bit, nur Hash gespeichert, 24 h gültig, atomar verbraucht | `TestEndToEnd` (zweite Verwendung scheitert) |
| Agent-Identität | Ed25519 pro Node, Schlüsseldatei 0600, Start verweigert bei offenen Rechten | `identity_test.go` |
| Schlüsselrotation | Admin fordert an; der Agent erzeugt einen neuen Schlüssel, legt ihn als `identity.key.next` ab, meldet ihn mit Signatur des alten Schlüssels und tauscht erst danach; ein Absturz dazwischen wird beim Neustart über das 401 erkannt | `TestKeyRotation`, `TestKeyRotationCrashRecovery` |
| Versionsschutz | Der Agent übernimmt nur Policies mit höherer Version als der aktiven; ein erneut eingespielter alter, gültig signierter Envelope wird abgelehnt | `TestOlderSignedPolicyIsRejected` |
| Abhängigkeiten | Go 1.27.2, pgx 5.11 (behebt GO-2026-5004), aktuelle `x/*`-Module; `npm audit` meldet 0 Funde; CI führt `govulncheck` und `npm audit` aus, Dependabot hält die Versionen aktuell | siehe `TEST-REPORT.md`, Abschnitt 6 |
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

- **MFA hat keine Recovery-Codes.** Einrichtung und Deaktivierung gehen über die Seite „Konto“. Bei Verlust des Geräts hilft nur ein Eingriff in der Datenbank (`UPDATE users SET totp_enabled=false, totp_secret_enc=NULL`).
- **MFA-Schlüssel hängt am Signaturschlüssel.** Das Verschlüsselungs-Geheimnis wird aus dem Panel-Signaturschlüssel abgeleitet. Ein Verlust dieses Schlüssels macht alle gespeicherten MFA-Geheimnisse unlesbar.
- **Signaturschlüssel des Panels** liegt als Datei (0600) auf dem Panel-Host. Ein HSM oder KMS ist vorgesehen, aber nicht umgesetzt. Ein Verlust des Schlüssels ist kritisch (siehe `OPERATIONS.md`, Backup).
- **Rotation des Panel-Signaturschlüssels ist nicht umgesetzt.** Node-Schlüssel lassen sich rotieren, der Schlüssel, mit dem das Panel Policies signiert, nicht. Ein Wechsel erfordert derzeit ein Neu-Enrollment aller Agents.
- **Kein Proxy-Vertrauen.** Das Panel nutzt nur die TCP-Gegenstelle als Client-IP. Hinter einem Reverse Proxy sind Rate-Limits daher pro Proxy-IP wirksam, nicht pro Client.
- **Panel-Heartbeat ist nicht gegen Schlüsselklau durch lokale root-Angreifer geschützt.** Wer root auf dem Node hat, kann den Agent übernehmen und Sperren setzen. Das ist ein Grundproblem jedes Host-Agents; die Schadensbegrenzung liegt in den Management-Netzen und Limits, nicht in der Identität.
