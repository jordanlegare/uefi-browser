#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="5.9.4"
ARCHIVE="wolfssl-$VERSION.zip"
URL="https://distfiles.macports.org/wolfssl/$ARCHIVE"
SHA256="9cd0d69d208d025b16836c177658cc0deebc2a85c4b60898c9bc546bc6cbdf18"
VENDOR="$ROOT/vendor"
DEST="$VENDOR/wolfssl-$VERSION"

mkdir -p "$VENDOR"
if [[ -f "$DEST/configure" && -f "$DEST/COPYING" ]]; then
  echo "wolfSSL $VERSION is already present at $DEST"
  exit 0
fi

rm -rf "$DEST"
curl --fail --location --retry 3 "$URL" -o "$VENDOR/$ARCHIVE"
echo "$SHA256  $VENDOR/$ARCHIVE" | sha256sum --check -
unzip -q "$VENDOR/$ARCHIVE" -d "$VENDOR"
rm -f "$VENDOR/$ARCHIVE"

test -f "$DEST/configure"
test -f "$DEST/COPYING"
echo "Verified wolfSSL $VERSION source at $DEST"
