#!/usr/bin/env bash
# Download the pinned OPA binary into .tools/bin and verify its SHA-256.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(cat "$ROOT/policy/OPA_VERSION")"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in x86_64|amd64) ARCH=amd64 ;; arm64|aarch64) ARCH=arm64 ;; *) echo "unsupported arch $ARCH"; exit 1 ;; esac
ASSET="opa_${OS}_${ARCH}"
[ "$OS/$ARCH" = "darwin/amd64" ] || ASSET="${ASSET}_static"
DEST="$ROOT/.tools/bin/opa"
EXPECTED="$(awk -v a="$ASSET" '$2==a {print $1}' "$ROOT/policy/OPA_SHA256")"
[ -n "$EXPECTED" ] || { echo "no pinned checksum for $ASSET"; exit 1; }
if [ -x "$DEST" ] && "$DEST" version | grep -q "Version: $VERSION"; then echo "opa $VERSION present"; exit 0; fi
mkdir -p "$(dirname "$DEST")"
TMP="$(mktemp)"
curl -fsSL -o "$TMP" "https://github.com/open-policy-agent/opa/releases/download/v${VERSION}/${ASSET}"
if command -v sha256sum >/dev/null; then ACTUAL="$(sha256sum "$TMP" | cut -d' ' -f1)"; else ACTUAL="$(shasum -a 256 "$TMP" | cut -d' ' -f1)"; fi
[ "$ACTUAL" = "$EXPECTED" ] || { echo "OPA checksum mismatch: $ACTUAL"; rm -f "$TMP"; exit 1; }
mv "$TMP" "$DEST"; chmod +x "$DEST"
echo "installed opa $VERSION ($ASSET) to $DEST"
