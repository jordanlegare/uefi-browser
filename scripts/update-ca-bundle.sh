#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSET_DIR="$ROOT/assets"
PEM="$ASSET_DIR/cacert.pem"
CHECKSUM="$ASSET_DIR/cacert.pem.sha256"
TMP_PEM="$PEM.tmp"
TMP_CHECKSUM="$CHECKSUM.tmp"
mkdir -p "$ASSET_DIR"
trap 'rm -f "$TMP_PEM" "$TMP_CHECKSUM"' EXIT
curl --fail --location --retry 3 https://curl.se/ca/cacert.pem -o "$TMP_PEM"
curl --fail --location --retry 3 https://curl.se/ca/cacert.pem.sha256 -o "$TMP_CHECKSUM"
EXPECTED="$(grep -Eo '[[:xdigit:]]{64}' "$TMP_CHECKSUM" | head -n 1 | tr 'A-F' 'a-f')"
ACTUAL="$(sha256sum "$TMP_PEM" | awk '{print $1}')"
if [[ -z "$EXPECTED" || "$ACTUAL" != "$EXPECTED" ]]; then
  echo "CA bundle checksum verification failed. Expected: $EXPECTED Actual: $ACTUAL" >&2
  exit 1
fi
grep -q -- "-----BEGIN CERTIFICATE-----" "$TMP_PEM" || { echo "Downloaded CA bundle is not PEM encoded." >&2; exit 1; }
grep -q 'Certificate data from Mozilla as of:' "$TMP_PEM" || { echo "Downloaded CA bundle has no Mozilla source-date metadata." >&2; exit 1; }
SOURCE_DATE="$(sed -n 's/^## Certificate data from Mozilla as of: //p' "$TMP_PEM" | head -n 1)"
CERT_COUNT="$(grep -c -- '-----BEGIN CERTIFICATE-----' "$TMP_PEM")"
if [[ -z "$SOURCE_DATE" || "$CERT_COUNT" -lt 1 ]]; then echo "Downloaded CA bundle metadata is incomplete." >&2; exit 1; fi
mv "$TMP_PEM" "$PEM"
mv "$TMP_CHECKSUM" "$CHECKSUM"
trap - EXIT
echo "Updated $PEM"
echo "Mozilla source date: $SOURCE_DATE"
echo "Certificates: $CERT_COUNT"
echo "SHA-256: $ACTUAL"
echo "Review Mozilla root-store changes before release."
