#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="4.3.0"
ARCHIVE="mbedtls-$VERSION.tar.bz2"
URL="https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-$VERSION/$ARCHIVE"
SHA256="1c87cba094cb40f097ebe0eba440a74939b71dab4e1d0d566bc90749ff381d18"
VENDOR="$ROOT/vendor"
DEST="$VENDOR/mbedtls-$VERSION"

mkdir -p "$VENDOR"
if [[ -d "$DEST" ]]; then
  echo "Mbed TLS $VERSION is already present at $DEST"
  exit 0
fi

curl --fail --location --retry 3 "$URL" -o "$VENDOR/$ARCHIVE"
echo "$SHA256  $VENDOR/$ARCHIVE" | sha256sum --check -
tar -xjf "$VENDOR/$ARCHIVE" -C "$VENDOR"
rm -f "$VENDOR/$ARCHIVE"

echo "Verified Mbed TLS $VERSION source at $DEST"
