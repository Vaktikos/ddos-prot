#!/usr/bin/env bash
# Sets up the Sentinel Shield panel with Docker Compose in one step.
#
#   git clone <repository> && cd ddos-prot
#   scripts/install-panel.sh --domain panel.example.net
#
# It generates the secrets (database password, administrator password), a TLS certificate
# (self-signed unless you pass --cert/--key or --letsencrypt), writes deploy/panel/.env with
# mode 0600, starts the stack and prints the address and the administrator login once.
# It does not overwrite an existing .env.
#
# Options:
#   --domain NAME        host name agents and browsers use (default: this host's name)
#   --port N             HTTPS port on the host (default: 8443)
#   --admin-email MAIL   login of the first administrator (default: admin@DOMAIN)
#   --cert FILE --key FILE   use your own certificate (PEM) instead of a self-signed one
#   --letsencrypt MAIL   obtain a certificate with certbot (needs port 80 free and a public name)
#   --no-start           only write the configuration (also needed for --dir)
#   --dir DIR            write .env and secrets there instead of deploy/panel (with --no-start)
#   --yes                do not ask questions
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_DIR="$REPO/deploy/panel"
TARGET="$COMPOSE_DIR"
DOMAIN="" PORT=8443 ADMIN_EMAIL="" CERT="" KEY="" LE_MAIL="" START=1 ASSUME_YES=0

log()  { printf '[panel] %s\n' "$*"; }
warn() { printf '[panel] WARNUNG: %s\n' "$*" >&2; }
die()  { printf '[panel] FEHLER: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    --admin-email) ADMIN_EMAIL="${2:-}"; shift 2 ;;
    --cert) CERT="${2:-}"; shift 2 ;;
    --key) KEY="${2:-}"; shift 2 ;;
    --letsencrypt) LE_MAIL="${2:-}"; shift 2 ;;
    --no-start) START=0; shift ;;
    --dir) TARGET="${2:-}"; shift 2 ;;
    --yes) ASSUME_YES=1; shift ;;
    -h|--help) usage 0 ;;
    *) die "unbekannte Option: $1 (siehe --help)" ;;
  esac
done

[[ "$TARGET" == "$COMPOSE_DIR" || $START -eq 0 ]] || die "--dir ist nur zusammen mit --no-start erlaubt"
command -v openssl >/dev/null 2>&1 || die "openssl wird zum Erzeugen der Geheimnisse benötigt"
[[ "$PORT" =~ ^[0-9]{1,5}$ && "$PORT" -ge 1 && "$PORT" -le 65535 ]] || die "ungültiger Port: $PORT"
if [[ -z "$DOMAIN" ]]; then DOMAIN="$(hostname -f 2>/dev/null || hostname)"; fi
[[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || die "ungültiger Domainname: $DOMAIN"
[[ "$DOMAIN" == *.* || "$DOMAIN" =~ ^[0-9.]+$ ]] || warn "'$DOMAIN' ist kein vollständiger Name; Agents anderer Hosts erreichen ihn so evtl. nicht (--domain angeben)"
[[ -n "$ADMIN_EMAIL" ]] || ADMIN_EMAIL="admin@$DOMAIN"
[[ "$ADMIN_EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]] || die "ungültige E-Mail-Adresse: $ADMIN_EMAIL"
[[ -z "$CERT" && -z "$KEY" ]] || { [[ -r "$CERT" && -r "$KEY" ]] || die "--cert und --key müssen beide lesbare Dateien sein"; }

if [[ $START -eq 1 ]]; then
  command -v docker >/dev/null 2>&1 || die "docker fehlt (https://docs.docker.com/engine/install/)"
  docker compose version >/dev/null 2>&1 || die "docker compose v2 fehlt"
  docker info >/dev/null 2>&1 || die "kein Zugriff auf den Docker-Daemon (Benutzer in der Gruppe 'docker' oder sudo?)"
fi

ENV_FILE="$TARGET/.env"
SECRETS="$TARGET/secrets"
if [[ -e "$ENV_FILE" ]]; then
  log "$ENV_FILE existiert bereits und bleibt unverändert."
  [[ $START -eq 1 ]] || exit 0
else
  umask 077
  mkdir -p "$SECRETS"; chmod 0700 "$SECRETS"

  # --- TLS ------------------------------------------------------------------------------
  SELF_SIGNED=0
  if [[ -n "$LE_MAIL" ]]; then
    command -v certbot >/dev/null 2>&1 || die "certbot fehlt (apt install certbot)"
    certbot certonly --standalone -d "$DOMAIN" --agree-tos -m "$LE_MAIL" -n || die "Let's Encrypt fehlgeschlagen"
    CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"; KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
  fi
  if [[ -n "$CERT" ]]; then
    install -m 0644 "$CERT" "$SECRETS/panel-cert.pem"
    install -m 0600 "$KEY" "$SECRETS/panel-key.pem"
  else
    SELF_SIGNED=1
    SAN="DNS:$DOMAIN"; [[ "$DOMAIN" =~ ^[0-9.]+$ ]] && SAN="IP:$DOMAIN"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 \
      -subj "/CN=$DOMAIN" -addext "subjectAltName=$SAN" \
      -keyout "$SECRETS/panel-key.pem" -out "$SECRETS/panel-cert.pem" 2>/dev/null || die "Zertifikat konnte nicht erzeugt werden"
    chmod 0600 "$SECRETS/panel-key.pem"; chmod 0644 "$SECRETS/panel-cert.pem"
  fi
  # The container user must be able to read the key it is mounted with.
  chmod 0644 "$SECRETS/panel-key.pem"

  # --- Secrets --------------------------------------------------------------------------
  DB_PASS="$(openssl rand -hex 24)"
  ADMIN_PASS="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-20)"
  printf '%s\n' "$ADMIN_PASS" > "$SECRETS/admin-password.txt"; chmod 0644 "$SECRETS/admin-password.txt"

  cat > "$ENV_FILE" <<ENV
# Generated by scripts/install-panel.sh. Contains secrets: never commit this file.
PANEL_PUBLIC_URL=https://$DOMAIN:$PORT
PANEL_HOST_PORT=$PORT

POSTGRES_DB=sentinel
POSTGRES_USER=sentinel
POSTGRES_PASSWORD=$DB_PASS
PANEL_DATABASE_URL=host=postgres port=5432 dbname=sentinel user=sentinel password=$DB_PASS sslmode=disable

PANEL_TLS_CERT=/run/secrets/panel-cert.pem
PANEL_TLS_KEY=/run/secrets/panel-key.pem

PANEL_ADMIN_EMAIL=$ADMIN_EMAIL
PANEL_ADMIN_PASSWORD_FILE=/run/secrets/admin-password.txt

PANEL_SESSION_HOURS=12
ENV
  chmod 0600 "$ENV_FILE"
  log "Konfiguration geschrieben: $ENV_FILE"
fi

if [[ $START -eq 0 ]]; then
  log "Nicht gestartet (--no-start)."; exit 0
fi

# --- Start ------------------------------------------------------------------------------
log "Baue und starte das Panel (das dauert beim ersten Mal einige Minuten) ..."
( cd "$COMPOSE_DIR" && docker compose up -d --build )
log "Warte auf Bereitschaft ..."
for _ in $(seq 1 60); do
  if curl -fsSk --max-time 3 "https://127.0.0.1:$PORT/readyz" >/dev/null 2>&1; then READY=1; break; fi
  sleep 2
done
[[ "${READY:-0}" -eq 1 ]] || die "das Panel wurde nicht bereit; Logs: (cd $COMPOSE_DIR && docker compose logs panel)"

ADMIN_SHOWN="$(cat "$SECRETS/admin-password.txt" 2>/dev/null || echo '(siehe secrets/admin-password.txt)')"
cat <<MSG

Das Panel läuft.

  Adresse:   https://$DOMAIN:$PORT
  Login:     $ADMIN_EMAIL
  Passwort:  $ADMIN_SHOWN        (nur jetzt ausgeben; danach $SECRETS/admin-password.txt löschen)

Nächste Schritte:
  1. Anmelden, unter "Konto" die Zwei-Faktor-Anmeldung einrichten und Recovery-Codes sichern.
  2. Ein Schutzprofil anlegen ("Profile", Vorlage wählen), dann einen Node ("Nodes").
  3. Auf dem Server den angezeigten Ein-Zeilen-Befehl ausführen.
MSG
if [[ "${SELF_SIGNED:-0}" -eq 1 ]]; then
  cat <<MSG

Hinweis: Das Zertifikat ist selbstsigniert. Browser warnen davor, und Agents brauchen es als CA:
  scp $SECRETS/panel-cert.pem server:/root/panel-ca.pem   und beim Installieren  --ca-file /root/panel-ca.pem
Für den Dauerbetrieb ein echtes Zertifikat verwenden (--letsencrypt oder --cert/--key).
MSG
fi
