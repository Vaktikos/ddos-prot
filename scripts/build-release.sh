#!/usr/bin/env bash
# Builds static agent binaries for linux/amd64 and linux/arm64 into dist/ with a SHA256SUMS file.
# Point PANEL_DOWNLOAD_DIR at dist/ to let a panel outside Docker serve them to the installer.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
OUT="${1:-dist}"
mkdir -p "$OUT"
for arch in amd64 arm64; do
  echo "[release] sentinel-agent linux/$arch"
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags="-s -w" -o "$OUT/sentinel-agent-linux-$arch" ./cmd/agent
done
(cd "$OUT" && sha256sum sentinel-agent-linux-* > SHA256SUMS && cat SHA256SUMS)
