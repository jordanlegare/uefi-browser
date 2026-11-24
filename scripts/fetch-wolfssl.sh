#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="5.9.4"
ARCHIVE="wolfssl-$VERSION.zip"
URL="https://distfiles.macports.org/wolfssl/$ARCHIVE"
SHA256="9cd0d69d208d025b16836c177658cc0deebc2a85c4b60898c9bc546bc6cbdf18"
VENDOR="$ROOT/vendor"
DEST="$VENDOR/wolfssl-$VERSION"
EXTRACT="$VENDOR/.wolfssl-$VERSION-extract"

mkdir -p "$VENDOR"
if [[ -f "$DEST/CMakeLists.txt" && -f "$DEST/COPYING" ]]; then
  echo "wolfSSL $VERSION is already present at $DEST"
  exit 0
fi

rm -rf "$DEST" "$EXTRACT"
curl --fail --location --retry 3 "$URL" -o "$VENDOR/$ARCHIVE"
echo "$SHA256  $VENDOR/$ARCHIVE" | sha256sum --check -
mkdir -p "$EXTRACT"
unzip -q "$VENDOR/$ARCHIVE" -d "$EXTRACT"
rm -f "$VENDOR/$ARCHIVE"

if [[ -f "$EXTRACT/CMakeLists.txt" ]]; then
  mv "$EXTRACT" "$DEST"
else
  SOURCE_DIR="$(find "$EXTRACT" -mindepth 1 -maxdepth 1 -type d -print -quit)"
  if [[ -z "$SOURCE_DIR" || ! -f "$SOURCE_DIR/CMakeLists.txt" ]]; then
    echo "wolfSSL archive has an unexpected directory layout." >&2
    exit 1
  fi
  mv "$SOURCE_DIR" "$DEST"
  rm -rf "$EXTRACT"
fi

test -f "$DEST/CMakeLists.txt"
test -f "$DEST/COPYING"
echo "Verified wolfSSL $VERSION source at $DEST"
