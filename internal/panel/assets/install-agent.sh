#!/usr/bin/env bash
# Sentinel Shield agent installer for Debian and Ubuntu.
#
# One line, run on the node (the panel shows this command after you create a node):
#   curl -fsSL @PANEL_URL@/install.sh | sudo bash -s -- --token <TOKEN> --management-cidr auto
#
# It checks the system, downloads the agent from the panel and verifies its SHA-256, writes
# the configuration, registers the node and starts the service. It never flushes or edits
# existing nftables rules: the agent only manages its own table, inet sentinel_shield.
#
# Options:
#   --panel URL            panel address (default: the panel that served this script)
#   --token TOKEN          one-time enrollment token; enrolls and starts the service
#   --binary PATH          use a local binary instead of downloading
#   --management-cidr C    networks that are never blocked, repeatable. "auto" uses the
#                          address of the current SSH session (needs sudo -E or root login)
#   --uplink IFACE|auto    interface for traffic statistics (default: auto, the default route)
#   --xdp off|auto|IFACE   enable the XDP early-drop filter (default: off)
#   --ca-file PATH         extra CA certificate for the panel
#   --root DIR             install below DIR and do not touch systemd (for testing)
#   --yes                  do not ask questions
#   --dry-run              show what would happen, change nothing
set -euo pipefail

PANEL="@PANEL_URL@"
[[ "$PANEL" == @* ]] && PANEL=""
TOKEN="" BINARY="" UPLINK="auto" XDP="off" CA_FILE="" ROOT="" ASSUME_YES=0 DRY_RUN=0
MGMT=()

log()  { printf '[install] %s\n' "$*"; }
warn() { printf '[install] WARNUNG: %s\n' "$*" >&2; }
die()  { printf '[install] FEHLER: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --panel) PANEL="${2:-}"; shift 2 ;;
    --token) TOKEN="${2:-}"; shift 2 ;;
    --binary) BINARY="${2:-}"; shift 2 ;;
    --management-cidr) MGMT+=("${2:-}"); shift 2 ;;
    --uplink) UPLINK="${2:-}"; shift 2 ;;
    --xdp) XDP="${2:-}"; shift 2 ;;
    --ca-file) CA_FILE="${2:-}"; shift 2 ;;
    --root) ROOT="${2:-}"; shift 2 ;;
    --yes) ASSUME_YES=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage 0 ;;
    *) die "unbekannte Option: $1 (siehe --help)" ;;
  esac
done

run() { if [[ $DRY_RUN -eq 1 ]]; then log "[dry-run] $*"; else "$@"; fi; }

confirm() {
  [[ $ASSUME_YES -eq 1 ]] && return 0
  if [[ -r /dev/tty ]]; then
    read -r -p "$1 [j/N] " answer < /dev/tty
    [[ "$answer" =~ ^[jJyY]$ ]]
  else
    die "keine Rückfrage möglich (kein Terminal): mit --yes bestätigen"
  fi
}

# Interface of the default route, in plain bash: mawk (the default awk on Debian and Ubuntu)
# has no and()/strtonum(). Flags bit 0x2 means "gateway"; destination 00000000 is the default.
default_route_iface() {
  local iface dest _gw flags _rest
  while read -r iface dest _gw flags _rest; do
    [[ "$dest" == "00000000" && "$iface" != "Iface" ]] || continue
    if (( 0x$flags & 2 )); then printf '%s' "$iface"; return; fi
  done < /proc/net/route 2>/dev/null
  # IPv6 only: destination ::/0 with prefix length 00, interface in the 10th column.
  local d p _a _b _c _d _e f g h
  while read -r d p _a _b _c _d _e f g h; do
    [[ "$d" == "00000000000000000000000000000000" && "$p" == "00" && -n "$h" ]] && { printf '%s' "$h"; return; }
  done < /proc/net/ipv6_route 2>/dev/null
  return 0
}

# --- 1. System ---------------------------------------------------------------------------
[[ -r /etc/os-release ]] || die "/etc/os-release fehlt"
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  debian:11|debian:12|debian:13|ubuntu:22.04|ubuntu:24.04|ubuntu:26.04) log "System: ${PRETTY_NAME}" ;;
  *) die "nicht unterstütztes System '${PRETTY_NAME:-unbekannt}' (unterstützt: Debian 11-13, Ubuntu 22.04/24.04)" ;;
esac
if [[ -z "$ROOT" ]]; then
  [[ $(id -u) -eq 0 ]] || die "bitte als root ausführen (sudo)"
  [[ -d /run/systemd/system ]] || die "systemd ist nicht aktiv"
fi
[[ -r /proc/net/dev && -r /proc/stat && -r /proc/meminfo ]] || die "procfs nicht lesbar"
case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "nicht unterstützte Architektur: $(uname -m)" ;;
esac

# --- 2. Eingaben prüfen ------------------------------------------------------------------
if [[ -z "$BINARY" ]]; then
  [[ -n "$PANEL" ]] || die "--panel URL oder --binary PFAD angeben"
  command -v curl >/dev/null 2>&1 || die "curl wird zum Herunterladen benötigt"
fi
[[ -z "$PANEL" || "$PANEL" =~ ^https://[A-Za-z0-9._:-]+(/[A-Za-z0-9._/-]*)?$ || "$PANEL" =~ ^http://(127\.0\.0\.1|localhost)(:[0-9]+)?$ ]] \
  || die "panel-URL muss https verwenden (http nur für localhost): $PANEL"
PANEL="${PANEL%/}"
[[ "$UPLINK" == "auto" || "$UPLINK" =~ ^[A-Za-z0-9._-]{1,15}$ ]] || die "ungültiger Interface-Name: $UPLINK"
[[ "$XDP" == "off" || "$XDP" == "auto" || "$XDP" =~ ^[A-Za-z0-9._-]{1,15}$ ]] || die "ungültiger Wert für --xdp: $XDP"
[[ -z "$TOKEN" || "$TOKEN" =~ ^[A-Za-z0-9_-]{20,128}$ ]] || die "der Enrollment-Token hat ein ungültiges Format"
[[ -z "$CA_FILE" || -r "$CA_FILE" ]] || die "CA-Datei nicht lesbar: $CA_FILE"

# Management networks: never blocked. "auto" takes the address of the current SSH session.
RESOLVED=()
for c in "${MGMT[@]+"${MGMT[@]}"}"; do
  if [[ "$c" == "auto" ]]; then
    ip="${SSH_CONNECTION%% *}"
    [[ -n "${SSH_CONNECTION:-}" && -n "$ip" ]] \
      || die "--management-cidr auto braucht eine SSH-Sitzung (bei sudo: sudo -E) – oder das Netz ausdrücklich angeben"
    if [[ "$ip" == *:* ]]; then c="$ip/128"; else c="$ip/32"; fi
    warn "Management-Netz aus der SSH-Sitzung: $c (ändert sich Ihre Adresse, die Konfiguration anpassen)"
  fi
  [[ "$c" =~ ^[0-9a-fA-F:.]+(/[0-9]{1,3})?$ ]] || die "ungültiges Management-Netz: $c"
  RESOLVED+=("$c")
done
[[ ${#RESOLVED[@]} -gt 0 ]] || die "--management-cidr ist Pflicht: Netze, die der Agent niemals sperrt (Ihr Zugang), oder 'auto'"

if [[ "$UPLINK" == "auto" ]]; then
  UPLINK="$(default_route_iface)"
  [[ -n "$UPLINK" ]] || die "Uplink-Interface nicht erkennbar: --uplink IFACE angeben"
  log "Uplink-Interface: $UPLINK"
fi
[[ "$XDP" == "auto" ]] && XDP="$UPLINK"

# --- 3. nftables und bestehende Regeln (nur lesen) ---------------------------------------
if ! command -v nft >/dev/null 2>&1; then
  log "nftables fehlt"
  confirm "nftables jetzt über apt installieren?" || die "nftables wird benötigt"
  run apt-get update -qq
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables
fi
NFT_BIN="$(command -v nft || echo /usr/sbin/nft)"
EXISTING="$(nft list ruleset 2>/dev/null || true)"
if [[ -n "$EXISTING" ]]; then
  warn "es existiert bereits ein nftables-Ruleset ($(printf '%s\n' "$EXISTING" | grep -c '^table ' || true) Tabellen)."
  warn "Der Agent legt nur 'inet sentinel_shield' an und ändert keine anderen Regeln."
  confirm "Mit der Installation fortfahren?" || die "abgebrochen, nichts wurde verändert"
fi

# --- 4. Binary beschaffen und prüfen --------------------------------------------------
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CURL=(curl -fsSL --proto '=https,http' --max-time 120)
[[ -n "$CA_FILE" ]] && CURL+=(--cacert "$CA_FILE")
if [[ -z "$BINARY" ]]; then
  NAME="sentinel-agent-linux-$ARCH"
  log "Lade $NAME von $PANEL"
  "${CURL[@]}" -o "$TMP/$NAME" "$PANEL/download/$NAME" || die "Download fehlgeschlagen"
  "${CURL[@]}" -o "$TMP/SHA256SUMS" "$PANEL/download/SHA256SUMS" || die "Prüfsummen nicht abrufbar"
  EXPECT="$(awk -v n="$NAME" '$2==n || $2=="*"n {print $1; exit}' "$TMP/SHA256SUMS")"
  [[ -n "$EXPECT" ]] || die "keine Prüfsumme für $NAME gefunden"
  ACTUAL="$(sha256sum "$TMP/$NAME" | awk '{print $1}')"
  [[ "$EXPECT" == "$ACTUAL" ]] || die "Prüfsumme stimmt nicht (erwartet $EXPECT, erhalten $ACTUAL): Binary wird NICHT installiert"
  log "SHA-256 geprüft: $ACTUAL"
  chmod 0755 "$TMP/$NAME"; BINARY="$TMP/$NAME"
fi
[[ -x "$BINARY" ]] || die "Binary nicht ausführbar: $BINARY"
VERSION="$("$BINARY" version 2>/dev/null || true)"
[[ -n "$VERSION" ]] || die "Binary liefert keine Version: $BINARY"
log "Agent-Version: $VERSION"

# --- 5. Installation ------------------------------------------------------------------------
BIN_DIR="$ROOT/usr/local/bin"; CONF_DIR="$ROOT/etc/sentinel-shield"; STATE_DIR="$ROOT/var/lib/sentinel-shield"
CONF="$CONF_DIR/agent.json"
run install -d -m 0755 "$BIN_DIR"
run install -m 0755 "$BINARY" "$BIN_DIR/sentinel-agent"
run install -d -m 0750 "$CONF_DIR"
run install -d -m 0700 "$STATE_DIR"

json_list() { local out="" x; for x in "$@"; do out+="\"$x\","; done; printf '[%s]' "${out%,}"; }

if [[ -e "$CONF" ]]; then
  log "vorhandene Konfiguration bleibt unverändert: $CONF"
else
  log "schreibe $CONF"
  XDP_JSON="[]"; [[ "$XDP" != "off" ]] && XDP_JSON="$(json_list "$XDP")"
  if [[ $DRY_RUN -eq 0 ]]; then
    cat > "$CONF" <<JSON
{
  "panel_url": "${PANEL:-https://panel.example.net:8443}",
  "ca_file": "${CA_FILE}",
  "state_dir": "/var/lib/sentinel-shield",
  "nft_binary": "${NFT_BIN}",
  "nft_table": "sentinel_shield",
  "uplink_interfaces": $(json_list "$UPLINK"),
  "management_cidrs": $(json_list "${RESOLVED[@]}"),
  "heartbeat_seconds": 30,
  "detect_interval_ms": 1000,
  "approval_timeout_seconds": 900,
  "xdp_interfaces": ${XDP_JSON},
  "xdp_mode": "auto"
}
JSON
    chmod 0640 "$CONF"
    # With --root the state directory lives below the staging root.
    [[ -n "$ROOT" ]] && sed -i "s#\"state_dir\": \"/var/lib/sentinel-shield\"#\"state_dir\": \"$STATE_DIR\"#" "$CONF"
  fi
fi

if [[ -z "$ROOT" ]]; then
  UNIT_SRC=""
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
  for cand in "$SCRIPT_DIR/sentinel-agent.service" "$SCRIPT_DIR/../deploy/agent/sentinel-agent.service"; do
    [[ -n "$SCRIPT_DIR" && -r "$cand" ]] && { UNIT_SRC="$cand"; break; }
  done
  if [[ -z "$UNIT_SRC" && -n "$PANEL" ]]; then
    "${CURL[@]}" -o "$TMP/sentinel-agent.service" "$PANEL/download/sentinel-agent.service" || die "systemd-Unit nicht abrufbar"
    UNIT_SRC="$TMP/sentinel-agent.service"
  fi
  [[ -n "$UNIT_SRC" ]] || die "systemd-Unit nicht gefunden"
  run install -m 0644 "$UNIT_SRC" /etc/systemd/system/sentinel-agent.service
  run systemctl daemon-reload
fi

# --- 6. Prüfen, registrieren, starten -------------------------------------------------------
if [[ $DRY_RUN -eq 0 ]]; then
  "$BIN_DIR/sentinel-agent" check --config "$CONF" || die "Prüfung fehlgeschlagen, siehe Meldung oben"
fi
if [[ -n "$TOKEN" && ! -f "$STATE_DIR/node.json" ]]; then
  run "$BIN_DIR/sentinel-agent" enroll --config "$CONF" --token "$TOKEN"
elif [[ -f "$STATE_DIR/node.json" ]]; then
  log "Node ist bereits eingeschrieben"
fi
if [[ -z "$ROOT" && ( -f "$STATE_DIR/node.json" || $DRY_RUN -eq 1 ) ]]; then
  run systemctl enable --now sentinel-agent.service
  [[ $DRY_RUN -eq 1 ]] || log "Dienst: $(systemctl is-active sentinel-agent.service || true)"
fi

if [[ ! -f "$STATE_DIR/node.json" && $DRY_RUN -eq 0 ]]; then
  cat <<MSG

Der Agent ist installiert, aber noch nicht registriert.
  1. Im Panel einen Node anlegen und den Token kopieren.
  2. sudo $BIN_DIR/sentinel-agent enroll --config $CONF --token <TOKEN>
  3. sudo systemctl enable --now sentinel-agent
MSG
else
  log "Fertig. Neue Nodes laufen im Modus 'dry_run': sie erkennen und melden, greifen aber nicht ein."
  log "Im Panel nach einigen Tagen Beobachtung auf 'mit Freigabe' oder 'automatisch' umstellen."
fi
