#!/usr/bin/env bash
# Installs the Sentinel Shield agent on a Debian or Ubuntu host.
#
# What it does:
#   - checks the operating system, root privileges, systemd and the nftables tools
#   - reports any existing nftables ruleset and NEVER flushes or edits it; the agent
#     only ever manages its own table, inet sentinel_shield
#   - installs the binary, creates state and configuration directories with restrictive modes
#   - writes a configuration only if none exists, and requires a management network
#   - installs the systemd unit; it is started only after the node is enrolled
#
# Usage:
#   sudo scripts/install-agent.sh --binary ./sentinel-agent --management-cidr 203.0.113.10/32 [--yes] [--dry-run]
set -euo pipefail

BINARY=""
MGMT_CIDRS=()
ASSUME_YES=0
DRY_RUN=0
PREFIX="/usr/local/bin"
CONF_DIR="/etc/sentinel-shield"
STATE_DIR="/var/lib/sentinel-shield"
UNIT_PATH="/etc/systemd/system/sentinel-agent.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_SRC="${SCRIPT_DIR}/../deploy/agent/sentinel-agent.service"
CONF_SRC="${SCRIPT_DIR}/../deploy/agent/agent.example.json"

log()  { printf '[install] %s\n' "$*"; }
warn() { printf '[install] WARNUNG: %s\n' "$*" >&2; }
die()  { printf '[install] FEHLER: %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary) BINARY="${2:-}"; shift 2 ;;
    --management-cidr) MGMT_CIDRS+=("${2:-}"); shift 2 ;;
    --yes) ASSUME_YES=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage 0 ;;
    *) die "unbekannte Option: $1" ;;
  esac
done

run() {
  if [[ $DRY_RUN -eq 1 ]]; then
    log "[dry-run] $*"
  else
    "$@"
  fi
}

confirm() {
  [[ $ASSUME_YES -eq 1 ]] && return 0
  read -r -p "$1 [j/N] " answer
  [[ "$answer" =~ ^[jJyY]$ ]]
}

# --- 1. Operating system and privileges -------------------------------------------------
[[ -r /etc/os-release ]] || die "/etc/os-release fehlt"
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  debian:11|debian:12|debian:13|ubuntu:22.04|ubuntu:24.04) log "System: ${PRETTY_NAME}" ;;
  *) die "nicht unterstütztes System '${PRETTY_NAME:-unbekannt}' (unterstützt: Debian 11-13, Ubuntu 22.04/24.04)" ;;
esac
[[ $(id -u) -eq 0 ]] || die "bitte als root ausführen (sudo)"
[[ -d /run/systemd/system ]] || die "systemd ist nicht aktiv"
[[ -r /proc/net/dev && -r /proc/stat && -r /proc/meminfo ]] || die "procfs nicht lesbar"

# --- 2. Inputs -------------------------------------------------------------------------------
[[ -n "$BINARY" ]] || die "--binary PFAD zum sentinel-agent Binary fehlt"
[[ -x "$BINARY" ]] || die "Binary nicht ausführbar: $BINARY"
[[ ${#MGMT_CIDRS[@]} -gt 0 ]] || die "--management-cidr ist Pflicht: Netze, die der Agent niemals sperrt (z. B. Ihr SSH-Zugang)"
for c in "${MGMT_CIDRS[@]}"; do
  [[ "$c" =~ ^[0-9a-fA-F:.]+(/[0-9]{1,3})?$ ]] || die "ungültiges Management-Netz: $c"
done

# --- 3. Dependencies -----------------------------------------------------------------------
if ! command -v nft >/dev/null 2>&1; then
  log "nftables fehlt"
  if confirm "nftables jetzt über apt installieren?"; then
    run apt-get update -qq
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables
  else
    die "nftables wird benötigt"
  fi
fi
NFT_BIN="$(command -v nft)"

# --- 4. Existing firewall state (read only) --------------------------------------------------
EXISTING="$(nft list ruleset 2>/dev/null || true)"
if [[ -n "$EXISTING" ]]; then
  TABLES=$(printf '%s\n' "$EXISTING" | grep -c '^table ' || true)
  warn "auf diesem Host existiert bereits ein nftables-Ruleset (${TABLES} Tabellen)."
  warn "Der Agent legt nur die Tabelle 'inet sentinel_shield' an und ändert keine anderen Regeln."
  warn "Prüfen Sie vorher: nft list ruleset"
  confirm "Mit der Installation fortfahren?" || die "abgebrochen, nichts wurde verändert"
else
  log "kein bestehendes nftables-Ruleset gefunden"
fi

# --- 5. Verify the binary ----------------------------------------------------------------
VERSION="$("$BINARY" version 2>/dev/null || true)"
[[ -n "$VERSION" ]] || die "Binary liefert keine Version: $BINARY"
log "Binary-Version: ${VERSION}"

# --- 6. Install --------------------------------------------------------------------------
run install -m 0755 -o root -g root "$BINARY" "${PREFIX}/sentinel-agent"
run install -d -m 0750 -o root -g root "$CONF_DIR"
run install -d -m 0700 -o root -g root "$STATE_DIR"

CONF="${CONF_DIR}/agent.json"
if [[ -e "$CONF" ]]; then
  log "vorhandene Konfiguration bleibt unverändert: $CONF"
else
  log "lege Konfiguration an: $CONF (Panel-URL danach eintragen)"
  if [[ $DRY_RUN -eq 0 ]]; then
    MGMT_JSON=$(printf '"%s",' "${MGMT_CIDRS[@]}"); MGMT_JSON="[${MGMT_JSON%,}]"
    sed -e "s#\"management_cidrs\": \[\"203.0.113.10/32\"\]#\"management_cidrs\": ${MGMT_JSON}#" \
        -e "s#\"nft_binary\": \"/usr/sbin/nft\"#\"nft_binary\": \"${NFT_BIN}\"#" "$CONF_SRC" > "$CONF"
    chmod 0640 "$CONF"; chown root:root "$CONF"
  fi
fi

run install -m 0644 -o root -g root "$UNIT_SRC" "$UNIT_PATH"
run systemctl daemon-reload

# --- 7. Validate without changing firewall rules ------------------------------------------------
if [[ $DRY_RUN -eq 0 ]]; then
  "${PREFIX}/sentinel-agent" check --config "$CONF" || die "Prüfung fehlgeschlagen, siehe Meldung oben"
fi

# --- 8. Start only when enrolled --------------------------------------------------------------
if [[ -f "${STATE_DIR}/node.json" ]]; then
  log "Node ist bereits eingeschrieben, Dienst wird gestartet"
  run systemctl enable --now sentinel-agent.service
else
  log "Installation abgeschlossen. Der Dienst startet erst nach der Registrierung."
  cat <<MSG

Nächste Schritte:
  1. Panel-URL und Management-Netze in ${CONF} prüfen.
  2. Node im Panel anlegen und den Enrollment-Token kopieren.
  3. sudo ${PREFIX}/sentinel-agent enroll --config ${CONF} --token <TOKEN>
  4. sudo systemctl enable --now sentinel-agent
  Hinweis: Der Modus 'dry_run' ist Standard. Erst nach Prüfung im Panel auf 'automatisch' umstellen.
MSG
fi
