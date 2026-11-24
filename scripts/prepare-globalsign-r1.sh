#!/usr/bin/env bash
# Prepare the UEFI trust input by adding the pinned GlobalSign Root R1 anchor.
# The checksum-verified Mozilla/curl source bundle is never modified.
set -euo pipefail

INPUT="${1:?usage: prepare-globalsign-r1.sh input.pem output.pem}"
OUTPUT="${2:?usage: prepare-globalsign-r1.sh input.pem output.pem}"

ROOT_R1_URL="https://secure.globalsign.net/cacert/Root-R1.crt"
ROOT_R1_SHA256="EBD41040E4BB3EC742C9E381D31EF2A41A48B6685C96E7CEF3C1DF6CD4331C99"
ROOT_R1_SKI="607B661A450D97CA89502F7D04CD34A8FFFCFD4B"

for tool in curl openssl awk grep sed tr date mktemp cat cp mv; do
  command -v "$tool" >/dev/null || {
    echo "Required tool not found: $tool" >&2
    exit 1
  }
done

[[ -s "$INPUT" ]] || {
  echo "Input CA bundle is missing or empty: $INPUT" >&2
  exit 1
}

OUTPUT_DIR="$(dirname "$OUTPUT")"
mkdir -p "$OUTPUT_DIR"
TMP_DIR="$(mktemp -d)"
TMP_OUTPUT="$(mktemp "$OUTPUT_DIR/.cacert-r1-input.XXXXXX")"
cleanup() {
  rm -rf "$TMP_DIR"
  rm -f "$TMP_OUTPUT"
}
trap cleanup EXIT

DOWNLOADED="$TMP_DIR/root-r1.crt"
ROOT_PEM="$TMP_DIR/root-r1.pem"
curl --fail --show-error --silent --location --retry 3 \
  --connect-timeout 20 --max-time 120 --proto '=https' --tlsv1.2 \
  "$ROOT_R1_URL" -o "$DOWNLOADED"

# GlobalSign publishes this certificate as DER. Accept PEM too, in case its
# repository changes the download representation without changing the cert.
if grep -q -- "-----BEGIN CERTIFICATE-----" "$DOWNLOADED"; then
  cp "$DOWNLOADED" "$ROOT_PEM"
else
  openssl x509 -inform DER -in "$DOWNLOADED" -out "$ROOT_PEM"
fi
openssl x509 -in "$ROOT_PEM" -noout >/dev/null

ACTUAL_SHA256="$(
  openssl x509 -in "$ROOT_PEM" -noout -fingerprint -sha256 \
    | sed 's/^[^=]*=//; s/://g' | tr '[:upper:]' '[:lower:]'
)"
if [[ "$ACTUAL_SHA256" != "$(printf '%s' "$ROOT_R1_SHA256" | tr '[:upper:]' '[:lower:]')" ]]; then
  echo "GlobalSign Root R1 SHA-256 pin mismatch; refusing to add the certificate." >&2
  echo "Expected: $ROOT_R1_SHA256" >&2
  echo "Actual:   $ACTUAL_SHA256" >&2
  exit 1
fi

ACTUAL_SKI="$(
  openssl x509 -in "$ROOT_PEM" -noout -ext subjectKeyIdentifier \
    | sed -n '2,$p' | tr -d '[:space:]:' | tr '[:upper:]' '[:lower:]'
)"
if [[ "$ACTUAL_SKI" != "$(printf '%s' "$ROOT_R1_SKI" | tr '[:upper:]' '[:lower:]')" ]]; then
  echo "GlobalSign Root R1 Subject Key Identifier mismatch; refusing to add the certificate." >&2
  echo "Expected: $ROOT_R1_SKI" >&2
  echo "Actual:   $ACTUAL_SKI" >&2
  exit 1
fi

SUBJECT="$(openssl x509 -in "$ROOT_PEM" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"
ISSUER="$(openssl x509 -in "$ROOT_PEM" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//')"
if [[ "$SUBJECT" != "$ISSUER" || "$SUBJECT" != *"CN=GlobalSign Root CA"* ]]; then
  echo "Downloaded certificate is not the expected self-issued GlobalSign Root CA R1." >&2
  echo "Subject: $SUBJECT" >&2
  echo "Issuer:  $ISSUER" >&2
  exit 1
fi
if ! openssl x509 -in "$ROOT_PEM" -noout -ext basicConstraints | grep -q 'CA:TRUE'; then
  echo "GlobalSign Root R1 does not assert CA:TRUE; refusing to add it." >&2
  exit 1
fi
if ! openssl x509 -in "$ROOT_PEM" -noout -checkend 0 >/dev/null 2>&1; then
  echo "GlobalSign Root R1 is expired; refusing to add an expired trust anchor." >&2
  exit 1
fi

# Parse the source bundle and compare certificate fingerprints so R1 is never
# appended twice if a future Mozilla/curl bundle starts carrying this root.
awk -v dir="$TMP_DIR" '
  /-----BEGIN CERTIFICATE-----/ {
    if (path != "") exit 2
    count++
    path = sprintf("%s/source-%05d.pem", dir, count)
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

MATCHES=0
for CERT in "$TMP_DIR"/source-*.pem; do
  [[ -f "$CERT" ]] || continue
  openssl x509 -in "$CERT" -noout >/dev/null 2>&1 || {
    echo "Invalid X.509 certificate in source CA bundle: $CERT" >&2
    exit 1
  }
  CERT_SHA256="$(
    openssl x509 -in "$CERT" -noout -fingerprint -sha256 \
      | sed 's/^[^=]*=//; s/://g' | tr '[:upper:]' '[:lower:]'
  )"
  if [[ "$CERT_SHA256" == "$(printf '%s' "$ROOT_R1_SHA256" | tr '[:upper:]' '[:lower:]')" ]]; then
    MATCHES=$((MATCHES + 1))
  fi
done

if (( MATCHES > 1 )); then
  echo "Source CA bundle contains GlobalSign Root R1 more than once; refusing duplicate anchors." >&2
  exit 1
fi

cp "$INPUT" "$TMP_OUTPUT"
if (( MATCHES == 0 )); then
  printf '\n' >> "$TMP_OUTPUT"
  cat "$ROOT_PEM" >> "$TMP_OUTPUT"
  echo "Added verified GlobalSign Root R1 to generated UEFI CA input."
else
  echo "Verified GlobalSign Root R1 is already present in the source CA bundle."
fi

mv "$TMP_OUTPUT" "$OUTPUT"
trap - EXIT
rm -rf "$TMP_DIR"
echo "GlobalSign Root R1 SHA-256: $ACTUAL_SHA256"
echo "GlobalSign Root R1 SKI: $ACTUAL_SKI"
echo "Prepared UEFI CA input: $OUTPUT"
