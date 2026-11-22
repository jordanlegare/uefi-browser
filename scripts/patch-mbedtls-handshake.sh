#!/usr/bin/env bash
set -euo pipefail

SRC="${1:?usage: patch-mbedtls-handshake.sh MbedTLS-source-directory}"
TLS12="$SRC/library/ssl_tls12_client.c"
TLS13="$SRC/library/ssl_tls13_client.c"
TLS13_GENERIC="$SRC/library/ssl_tls13_generic.c"
X509="$SRC/library/x509_crt.c"

python3 - "$TLS12" "$TLS13" "$TLS13_GENERIC" "$X509" <<'PY'
from pathlib import Path
import sys

tls12, tls13, tls13_generic, x509 = map(Path, sys.argv[1:])

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

# X.509 verifier checkpoints: distinguish firmware time, chain construction,
# issuer/signature search, hashing, and public-key verification.
text = insert_declaration(x509)

old_time = """#if defined(MBEDTLS_HAVE_TIME_DATE)
    if (mbedtls_x509_time_gmtime(mbedtls_time(NULL), &now) != 0) {
        return MBEDTLS_ERR_X509_FATAL_ERROR;
    }
#endif"""
new_time = """#if defined(MBEDTLS_HAVE_TIME_DATE)
    uefi_browser_tls_log(68, 0);
    if (mbedtls_x509_time_gmtime(mbedtls_time(NULL), &now) != 0) {
        uefi_browser_tls_log(69, MBEDTLS_ERR_X509_FATAL_ERROR);
        return MBEDTLS_ERR_X509_FATAL_ERROR;
    }
    uefi_browser_tls_log(69, 0);
#endif"""
if old_time in text:
    text = text.replace(old_time, new_time, 1)
elif new_time not in text:
    raise SystemExit(f"{x509}: expected X.509 time initialization not found")

old_chain = """    /* Check the chain */
    ret = x509_crt_verify_chain(crt, trust_ca, ca_crl,
                                f_ca_cb, p_ca_cb, profile,
                                &ver_chain, rs_ctx);"""
new_chain = """    /* Check the chain */
    uefi_browser_tls_log(70, 0);
    ret = x509_crt_verify_chain(crt, trust_ca, ca_crl,
                                f_ca_cb, p_ca_cb, profile,
                                &ver_chain, rs_ctx);
    uefi_browser_tls_log(71, ret);"""
if old_chain in text:
    text = text.replace(old_chain, new_chain, 1)
elif new_chain not in text:
    raise SystemExit(f"{x509}: expected certificate-chain verification call not found")

old_parent = """        ret = x509_crt_find_parent(child, cur_trust_ca, &parent,
                                   &parent_is_trusted, &signature_is_good,
                                   ver_chain->len - 1, self_cnt, rs_ctx,
                                   &now);"""
new_parent = """        uefi_browser_tls_log(72, (int) ver_chain->len);
        ret = x509_crt_find_parent(child, cur_trust_ca, &parent,
                                   &parent_is_trusted, &signature_is_good,
                                   ver_chain->len - 1, self_cnt, rs_ctx,
                                   &now);
        uefi_browser_tls_log(73, ret);"""
if old_parent in text:
    text = text.replace(old_parent, new_parent, 1)
elif new_parent not in text:
    raise SystemExit(f"{x509}: expected issuer search call not found")

old_hash = """    status = psa_hash_compute(hash_alg,
                              child->tbs.p,
                              child->tbs.len,
                              hash,
                              sizeof(hash),
                              &hash_len);"""
new_hash = """    uefi_browser_tls_log(74, (int) child->tbs.len);
    status = psa_hash_compute(hash_alg,
                              child->tbs.p,
                              child->tbs.len,
                              hash,
                              sizeof(hash),
                              &hash_len);
    uefi_browser_tls_log(75, (int) status);"""
if old_hash in text:
    text = text.replace(old_hash, new_hash, 1)
elif new_hash not in text:
    raise SystemExit(f"{x509}: expected certificate signature hash call not found")

old_verify = """    return mbedtls_pk_verify_ext(child->sig_pk, &parent->pk,
                                 child->sig_md, hash, hash_len,
                                 child->sig.p, child->sig.len);"""
new_verify = """    {
        int verify_ret;
        uefi_browser_tls_log(76, (int) child->sig_pk);
        verify_ret = mbedtls_pk_verify_ext(child->sig_pk, &parent->pk,
                                           child->sig_md, hash, hash_len,
                                           child->sig.p, child->sig.len);
        uefi_browser_tls_log(77, verify_ret);
        return verify_ret;
    }"""
if old_verify in text:
    text = text.replace(old_verify, new_verify, 1)
elif new_verify not in text:
    raise SystemExit(f"{x509}: expected public-key signature verification call not found")

x509.write_text(text)

print("Mbed TLS TLS and X.509 verification checkpoints installed (or already present).")
PY
