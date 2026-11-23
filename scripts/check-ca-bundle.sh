#!/usr/bin/env bash
# Source from build-uefi.sh or execute directly to validate the CA asset.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PEM="$ROOT/assets/cacert.pem"
CHECKSUM="$ROOT/assets/cacert.pem.sha256"
MAX_AGE_DAYS="${UEFI_CA_MAX_AGE_DAYS:-90}"
[[ "$MAX_AGE_DAYS" =~ ^[0-9]+$ ]] || { echo "UEFI_CA_MAX_AGE_DAYS must be a non-negative integer." >&2; return 1 2>/dev/null || exit 1; }
fail() { echo "$1" >&2; return 1 2>/dev/null || exit 1; }
[[ -s "$PEM" && -s "$CHECKSUM" ]] || fail "CA bundle/checksum missing; run scripts/update-ca-bundle.sh."
EXPECTED="$(grep -Eo '[[:xdigit:]]{64}' "$CHECKSUM" | head -n 1 | tr 'A-F' 'a-f')"
ACTUAL="$(sha256sum "$PEM" | awk '{print $1}')"
[[ -n "$EXPECTED" && "$ACTUAL" == "$EXPECTED" ]] || fail "CA bundle checksum mismatch; refusing an unverified trust store."
UEFI_CA_BUNDLE_SOURCE_DATE="$(sed -n 's/^## Certificate data from Mozilla as of: //p' "$PEM" | head -n 1)"
UEFI_CA_BUNDLE_CERT_COUNT="$(grep -c -- '-----BEGIN CERTIFICATE-----' "$PEM")"
[[ -n "$UEFI_CA_BUNDLE_SOURCE_DATE" && "$UEFI_CA_BUNDLE_CERT_COUNT" -gt 0 ]] || fail "CA bundle source date or certificate data missing."
SOURCE_EPOCH="$(date -u -d "$UEFI_CA_BUNDLE_SOURCE_DATE" +%s 2>/dev/null)" || fail "Cannot parse Mozilla CA source date: $UEFI_CA_BUNDLE_SOURCE_DATE"
NOW_EPOCH="$(date -u +%s)"
(( SOURCE_EPOCH <= NOW_EPOCH )) || fail "Mozilla CA bundle source date is in the future."
AGE_SECONDS=$((NOW_EPOCH - SOURCE_EPOCH))
MAX_AGE_SECONDS=$((MAX_AGE_DAYS * 86400))
(( AGE_SECONDS <= MAX_AGE_SECONDS )) || fail "Mozilla CA bundle is stale (${AGE_SECONDS}s old; maximum ${MAX_AGE_DAYS} days). Run scripts/update-ca-bundle.sh."
UEFI_CA_BUNDLE_SHA256="$ACTUAL"
export UEFI_CA_BUNDLE_SOURCE_DATE UEFI_CA_BUNDLE_CERT_COUNT UEFI_CA_BUNDLE_SHA256
echo "Verified Mozilla CA bundle: source='$UEFI_CA_BUNDLE_SOURCE_DATE', certificates=$UEFI_CA_BUNDLE_CERT_COUNT, sha256=$UEFI_CA_BUNDLE_SHA256, max_age_days=$MAX_AGE_DAYS"
