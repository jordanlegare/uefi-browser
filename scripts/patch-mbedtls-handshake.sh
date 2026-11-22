#!/usr/bin/env bash
set -euo pipefail

SRC="${1:?usage: patch-mbedtls-handshake.sh MbedTLS-source-directory}"
TLS12="$SRC/library/ssl_tls12_client.c"
TLS13="$SRC/library/ssl_tls13_client.c"

python3 - "$TLS12" "$TLS13" <<'PY'
from pathlib import Path
import sys

tls12, tls13 = map(Path, sys.argv[1:])

def insert_declaration(path: Path) -> str:
    text = path.read_text()
    declaration = "extern void uefi_browser_tls_log(int stage, int detail);"
    if declaration not in text:
        marker = "#include "
        pos = text.find(marker)
        if pos < 0:
            raise SystemExit(f"{path}: include block not found; refusing patch")
        text = text[:pos] + declaration + "\n" + text[pos:]
    return text

# TLS 1.2: state 3 dispatches directly to mbedtls_ssl_parse_certificate().
text = insert_declaration(tls12)
old12 = """        case MBEDTLS_SSL_SERVER_CERTIFICATE:
            ret = mbedtls_ssl_parse_certificate(ssl);
            break;"""
new12 = """        case MBEDTLS_SSL_SERVER_CERTIFICATE:
            uefi_browser_tls_log(55, ssl->state);
            ret = mbedtls_ssl_parse_certificate(ssl);
            uefi_browser_tls_log(56, ret);
            break;"""
if old12 in text:
    text = text.replace(old12, new12, 1)
elif new12 not in text:
    raise SystemExit(f"{tls12}: expected TLS 1.2 certificate dispatch not found")
tls12.write_text(text)

# TLS 1.3: state 3 dispatches through ssl_tls13_process_server_certificate().
text = insert_declaration(tls13)
old13 = """    ret = mbedtls_ssl_tls13_process_certificate(ssl);
    if (ret != 0) {"""
new13 = """    uefi_browser_tls_log(57, ssl->state);
    ret = mbedtls_ssl_tls13_process_certificate(ssl);
    uefi_browser_tls_log(58, ret);
    if (ret != 0) {"""
if old13 in text:
    text = text.replace(old13, new13, 1)
elif new13 not in text:
    raise SystemExit(f"{tls13}: expected TLS 1.3 certificate processor not found")
tls13.write_text(text)

print("Mbed TLS server-certificate checkpoints installed (or already present).")
PY
