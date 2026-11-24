#!/usr/bin/env bash
# Build a date-valid subset for wolfSSL's embedded UEFI trust store.
# The source Mozilla/curl bundle remains intact and checksum-verified.
set -euo pipefail

INPUT="${1:?usage: filter-ca-bundle.sh input.pem output.pem}"
OUTPUT="${2:?usage: filter-ca-bundle.sh input.pem output.pem}"

for tool in openssl awk date sed cat mktemp; do
  command -v "$tool" >/dev/null || {
    echo "Required tool not found: $tool" >&2
    exit 1
  }
done
[[ -s "$INPUT" ]] || { echo "Input CA bundle is empty: $INPUT" >&2; exit 1; }

OUTPUT_DIR="$(dirname "$OUTPUT")"
mkdir -p "$OUTPUT_DIR"
TMP_DIR="$(mktemp -d)"
TMP_OUTPUT="$(mktemp "$OUTPUT_DIR/.cacert-uefi.XXXXXX")"
cleanup() {
  rm -rf "$TMP_DIR"
  rm -f "$TMP_OUTPUT"
}
trap cleanup EXIT

awk -v dir="$TMP_DIR" '
  /-----BEGIN CERTIFICATE-----/ {
    if (path != "") exit 2
    count++
    path = sprintf("%s/cert-%05d.pem", dir, count)
  }
  path != "" { print > path }
  /-----END CERTIFICATE-----/ {
    if (path == "") exit 2
    close(path)
    path = ""
  }
  END {
    if (path != "") exit 2
    if (count == 0) exit 3
  }
' "$INPUT" || {
  echo "Malformed PEM certificate boundaries in $INPUT" >&2
  exit 1
}

NOW_EPOCH="$(date -u +%s)"
KEPT=0
EXPIRED=0
NOT_YET_VALID=0

for CERT in "$TMP_DIR"/cert-*.pem; do
  [[ -f "$CERT" ]] || continue
  openssl x509 -in "$CERT" -noout >/dev/null 2>&1 || {
    echo "Invalid X.509 certificate in source CA bundle." >&2
    exit 1
  }

  if ! openssl x509 -in "$CERT" -noout -checkend 0 >/dev/null 2>&1; then
    EXPIRED=$((EXPIRED + 1))
    continue
  fi

  START_DATE="$(openssl x509 -in "$CERT" -noout -startdate | sed 's/^notBefore=//')"
  START_EPOCH="$(date -u -d "$START_DATE" +%s)" || {
    echo "Cannot parse certificate notBefore date: $START_DATE" >&2
    exit 1
  }
  if (( START_EPOCH > NOW_EPOCH )); then
    NOT_YET_VALID=$((NOT_YET_VALID + 1))
    continue
  fi

  cat "$CERT" >> "$TMP_OUTPUT"
  KEPT=$((KEPT + 1))
done

if (( KEPT == 0 )); then
  echo "No currently valid CA certificates remain after filtering." >&2
  exit 1
fi

# Ensure the output is a valid non-empty PEM bundle before replacing it.
[[ "$(grep -c -- '-----BEGIN CERTIFICATE-----' "$TMP_OUTPUT")" -eq "$KEPT" ]]
mv "$TMP_OUTPUT" "$OUTPUT"
echo "UEFI CA bundle: kept=$KEPT expired_removed=$EXPIRED not_yet_valid_removed=$NOT_YET_VALID"
