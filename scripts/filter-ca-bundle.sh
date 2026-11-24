#!/usr/bin/env bash
# Produce a UEFI trust bundle containing only currently valid CA certificates.
# The original curl/Mozilla bundle remains checksum-verified and unmodified.
set -euo pipefail

INPUT="${1:?usage: filter-ca-bundle.sh input.pem output.pem}"
OUTPUT="${2:?usage: filter-ca-bundle.sh input.pem output.pem}"
command -v openssl >/dev/null
command -v awk >/dev/null
command -v date >/dev/null

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
mkdir -p "$(dirname "$OUTPUT")"
: > "$OUTPUT"

awk -v dir="$TMP_DIR" '
  /-----BEGIN CERTIFICATE-----/ {
    count++
    path = sprintf("%s/cert-%05d.pem", dir, count)
  }
  path != "" { print > path }
  /-----END CERTIFICATE-----/ {
    close(path)
    path = ""
  }
  END {
    if (path != "") exit 2
    if (count == 0) exit 3
  }
' "$INPUT"

NOW="$(date -u +%s)"
KEPT=0
EXPIRED=0
NOT_YET_VALID=0
for CERT in "$TMP_DIR"/cert-*.pem; do
  [[ -f "$CERT" ]] || continue
  if ! openssl x509 -in "$CERT" -noout >/dev/null 2>&1; then
    echo "Invalid certificate in source CA bundle: $CERT" >&2
    exit 1
  fi
  if ! openssl x509 -in "$CERT" -noout -checkend 0 >/dev/null 2>&1; then
    EXPIRED=$((EXPIRED + 1))
    continue
  fi
  START_DATE="$(openssl x509 -in "$CERT" -noout -startdate | sed 's/^notBefore=//')"
  START_EPOCH="$(date -u -d "$START_DATE" +%s)"
  if (( START_EPOCH > NOW )); then
    NOT_YET_VALID=$((NOT_YET_VALID + 1))
    continue
  fi
  cat "$CERT" >> "$OUTPUT"
  KEPT=$((KEPT + 1))
done

if (( KEPT == 0 )); then
  echo "No currently valid CA certificates remain after filtering." >&2
  exit 1
fi
echo "UEFI CA bundle: kept=$KEPT expired_removed=$EXPIRED not_yet_valid_removed=$NOT_YET_VALID"
