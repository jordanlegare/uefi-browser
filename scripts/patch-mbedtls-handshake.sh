#!/usr/bin/env bash
set -euo pipefail

SRC="${1:?usage: patch-mbedtls-handshake.sh MbedTLS-source-directory}"
TLS12="$SRC/library/ssl_tls12_client.c"
TLS13="$SRC/library/ssl_tls13_client.c"
TLS13_GENERIC="$SRC/library/ssl_tls13_generic.c"

python3 - "$TLS12" "$TLS13" "$TLS13_GENERIC" <<'PY'
from pathlib import Path
import sys

tls12, tls13, tls13_generic = map(Path, sys.argv[1:])

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


# TLS 1.3 internals: isolate message receive, DER parsing, chain validation,
# and transcript hashing. These markers run at function boundaries, not BIO callbacks.
text = insert_declaration(tls13_generic)
old_steps = """    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_tls13_fetch_handshake_msg(
                             ssl, MBEDTLS_SSL_HS_CERTIFICATE,
                             &buf, &buf_len));

    /* Parse the certificate chain sent by the peer. */
    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_tls13_parse_certificate(ssl, buf,
                                                             buf + buf_len));
    /* Validate the certificate chain and set the verification results. */
    MBEDTLS_SSL_PROC_CHK(ssl_tls13_validate_certificate(ssl));

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_add_hs_msg_to_checksum(
                             ssl, MBEDTLS_SSL_HS_CERTIFICATE, buf, buf_len));"""
new_steps = """    ret = mbedtls_ssl_tls13_fetch_handshake_msg(
              ssl, MBEDTLS_SSL_HS_CERTIFICATE, &buf, &buf_len);
    uefi_browser_tls_log(60, ret);
    if (ret != 0) {
        goto cleanup;
    }

    /* Parse the certificate chain sent by the peer. */
    uefi_browser_tls_log(61, (int) buf_len);
    ret = mbedtls_ssl_tls13_parse_certificate(ssl, buf, buf + buf_len);
    uefi_browser_tls_log(62, ret);
    if (ret != 0) {
        goto cleanup;
    }

    /* Validate the certificate chain and set the verification results. */
    uefi_browser_tls_log(63, 0);
    ret = ssl_tls13_validate_certificate(ssl);
    uefi_browser_tls_log(64, ret);
    if (ret != 0) {
        goto cleanup;
    }

    uefi_browser_tls_log(65, (int) buf_len);
    ret = mbedtls_ssl_add_hs_msg_to_checksum(
              ssl, MBEDTLS_SSL_HS_CERTIFICATE, buf, buf_len);
    uefi_browser_tls_log(66, ret);
    if (ret != 0) {
        goto cleanup;
    }"""
if old_steps in text:
    text = text.replace(old_steps, new_steps, 1)
elif new_steps not in text:
    raise SystemExit(f"{tls13_generic}: expected TLS 1.3 certificate processing sequence not found")

# Place checkpoints around the first debug callback using a narrow,
# formatting-independent match against the pinned Mbed TLS source.
debug_line = '    MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse certificate"));'
instrumented_debug = """    uefi_browser_tls_log(59, 0);
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse certificate"));
    uefi_browser_tls_log(67, 0);"""
if debug_line in text:
    text = text.replace(debug_line, instrumented_debug, 1)
elif instrumented_debug not in text:
    raise SystemExit(f"{tls13_generic}: expected initial certificate debug call not found")

tls13_generic.write_text(text)

print("Mbed TLS server-certificate checkpoints installed (or already present).")
PY
