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

# Trace trusted-parent selection without changing the verifier's decisions.
# These messages are emitted only for candidates whose subject DN exactly
# matches the child's issuer DN, keeping the firmware trace bounded.
debug_decl = "extern void uefi_browser_tls_debug_log(int level, const char *file, int line, const char *message);"
if debug_decl not in text:
    marker = "extern void uefi_browser_tls_log(int stage, int detail);"
    if marker not in text:
        raise SystemExit(f"{x509}: X.509 diagnostic declaration point not found")
    text = text.replace(marker, marker + "\n" + debug_decl, 1)

parent_trace_helper = """static void uefi_x509_buf_hex(
    const mbedtls_x509_buf *buf,
    char *out,
    size_t out_len)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t i;
    size_t used = 0;

    if (out_len == 0) {
        return;
    }
    out[0] = '\\0';
    if (buf == NULL || buf->p == NULL) {
        (void) mbedtls_snprintf(out, out_len, "-");
        return;
    }
    for (i = 0; i < buf->len && used + 2 < out_len; i++) {
        out[used++] = hex[buf->p[i] >> 4];
        out[used++] = hex[buf->p[i] & 0x0F];
    }
    out[used] = '\\0';
}

static void uefi_x509_parent_trace(
    const mbedtls_x509_crt *child,
    const mbedtls_x509_crt *parent,
    int top,
    unsigned path_cnt,
    const char *phase,
    int parent_check_ret,
    int key_usage_ret,
    int path_ok,
    int signature_ret,
    int time_ok)
{
    char child_subject[256];
    char child_issuer[256];
    char parent_subject[256];
    char parent_issuer[256];
    char parent_ski[96];
    char child_aki[96];
    char message[1800];
    const char *decision = "TRACE_ONLY";

    /*
     * Translate the low-level verifier result into a short, readable verdict.
     * In particular, distinguish an ECP restart from a real signature failure.
     */
    if (strcmp(phase, "candidate") == 0) {
        if (parent_check_ret != 0) {
            decision = "REJECTED_PARENT_CONSTRAINTS";
        } else if (!path_ok) {
            decision = "REJECTED_PATH_LENGTH";
        } else {
            decision = "CANDIDATE_PASSED_BASIC_CHECKS";
        }
    } else if (strcmp(phase, "signature") == 0) {
        if (signature_ret == MBEDTLS_ERR_ECP_IN_PROGRESS) {
            decision = "ECDSA_CHECK_STILL_RUNNING";
        } else if (signature_ret == 0) {
            decision = "SIGNATURE_VALID";
        } else {
            decision = "SIGNATURE_FAILED";
        }
    } else if (strcmp(phase, "time") == 0) {
        decision = time_ok ? "CERTIFICATE_TIME_VALID" :
                             "CERTIFICATE_EXPIRED_OR_NOT_YET_VALID";
    } else if (strcmp(phase, "path-length-reject") == 0) {
        decision = "REJECTED_PATH_LENGTH";
    } else if (strcmp(phase, "selected") == 0) {
        decision = top ? "TRUSTED_PARENT_SELECTED" : "PEER_CHAIN_PARENT_SELECTED";
    }

    (void) mbedtls_x509_dn_gets(child_subject, sizeof(child_subject), &child->subject);
    (void) mbedtls_x509_dn_gets(child_issuer, sizeof(child_issuer), &child->issuer);
    (void) mbedtls_x509_dn_gets(parent_subject, sizeof(parent_subject), &parent->subject);
    (void) mbedtls_x509_dn_gets(parent_issuer, sizeof(parent_issuer), &parent->issuer);
    uefi_x509_buf_hex(&parent->subject_key_id, parent_ski, sizeof(parent_ski));
    uefi_x509_buf_hex(&child->authority_key_id.keyIdentifier, child_aki, sizeof(child_aki));

    (void) mbedtls_snprintf(
        message, sizeof(message),
        "verdict=%s phase=%s search=%s path=%u child-subject=%s child-issuer=%s "
        "parent-subject=%s parent-issuer=%s parent-ski=%s child-aki=%s "
        "parent-check=%d ca=%d key-usage=0x%04lx keyCertSign-check=%d "
        "max-pathlen=%d path-ok=%d signature-ret=%d sig-md=%d sig-pk=%d time-ok=%d",
        decision, phase, top ? "TRUST_STORE" : "PEER_CHAIN",
        path_cnt, child_subject, child_issuer, parent_subject, parent_issuer,
        parent_ski, child_aki, parent_check_ret, parent->ca_istrue,
        (unsigned long) parent->key_usage, key_usage_ret,
        parent->max_pathlen, path_ok, signature_ret,
        child->sig_md, child->sig_pk, time_ok);
    uefi_browser_tls_debug_log(1, "x509-parent", (int) path_cnt, message);
}

"""
helper_marker = "static int x509_crt_find_parent_in("
if helper_marker not in text:
    raise SystemExit(f"{x509}: parent-search function marker not found")

# The build directory may already contain the helper from an earlier version
# of this patcher. Detect it by its function signature, not by comparing the
# entire body: the body intentionally evolves as diagnostics improve.
helper_signature = "static void uefi_x509_parent_trace("
helper_prefix_signature = "static void uefi_x509_buf_hex("
helper_start = text.find(helper_prefix_signature)
if helper_start < 0:
    helper_start = text.find(helper_signature)
if helper_start >= 0:
    # Replace the complete existing helper block, including the SKI/AKI
    # formatter when present. This keeps repeated patch runs idempotent.
    helper_end = text.find(helper_marker, helper_start)
    if helper_end < 0:
        raise SystemExit(f"{x509}: existing parent-trace helper has no end marker")
    text = text[:helper_start] + parent_trace_helper + text[helper_end:]
else:
    text = text.replace(helper_marker, parent_trace_helper + helper_marker, 1)

old_parent_loop = """    for (parent = candidates; parent != NULL; parent = parent->next) {
        /* basic parenting skills (name, CA bit, key usage) */
        if (x509_crt_check_parent(child, parent, top) != 0) {
            continue;
        }

        /* +1 because stored max_pathlen is 1 higher that the actual value */
        if (parent->max_pathlen > 0 &&
            (size_t) parent->max_pathlen < 1 + path_cnt - self_cnt) {
            continue;
        }

        /* Signature */
#if defined(MBEDTLS_ECP_RESTARTABLE)
check_signature:
#endif
        ret = x509_crt_check_signature(child, parent, rs_ctx);

#if defined(MBEDTLS_ECP_RESTARTABLE)
        if (rs_ctx != NULL && ret == MBEDTLS_ERR_ECP_IN_PROGRESS) {
            /* save state */
            rs_ctx->parent = parent;
            rs_ctx->fallback_parent = fallback_parent;
            rs_ctx->fallback_signature_is_good = fallback_signature_is_good;

            return ret;
        }
#else
        (void) ret;
#endif

        signature_is_good = ret == 0;
        if (top && !signature_is_good) {
            continue;
        }

#if defined(MBEDTLS_HAVE_TIME_DATE)
        /* optional time check */
        if (mbedtls_x509_time_cmp(&parent->valid_to, now) < 0 ||    /* past */
            mbedtls_x509_time_cmp(&parent->valid_from, now) > 0) {  /* future */
            if (fallback_parent == NULL) {
                fallback_parent = parent;
                fallback_signature_is_good = signature_is_good;
            }

            continue;
        }
#else
        ((void) now);
#endif

        *r_parent = parent;
        *r_signature_is_good = signature_is_good;

        break;
    }"""
new_parent_loop = """    for (parent = candidates; parent != NULL; parent = parent->next) {
        if (x509_name_cmp(&child->issuer, &parent->subject) == 0) {
            uefi_x509_parent_trace(
                child, parent, top, path_cnt, "candidate",
                x509_crt_check_parent(child, parent, top),
                mbedtls_x509_crt_check_key_usage(parent, MBEDTLS_X509_KU_KEY_CERT_SIGN),
                !(parent->max_pathlen > 0 &&
                  (size_t) parent->max_pathlen < 1 + path_cnt - self_cnt),
                -999, -1);
        }

        /* basic parenting skills (name, CA bit, key usage) */
        if (x509_crt_check_parent(child, parent, top) != 0) {
            continue;
        }

        /* +1 because stored max_pathlen is 1 higher that the actual value */
        if (parent->max_pathlen > 0 &&
            (size_t) parent->max_pathlen < 1 + path_cnt - self_cnt) {
            if (x509_name_cmp(&child->issuer, &parent->subject) == 0) {
                uefi_x509_parent_trace(
                    child, parent, top, path_cnt, "path-length-reject",
                    0, mbedtls_x509_crt_check_key_usage(parent, MBEDTLS_X509_KU_KEY_CERT_SIGN),
                    0, -999, -1);
            }
            continue;
        }

        /* Signature */
#if defined(MBEDTLS_ECP_RESTARTABLE)
check_signature:
#endif
        ret = x509_crt_check_signature(child, parent, rs_ctx);
        if (x509_name_cmp(&child->issuer, &parent->subject) == 0) {
            uefi_x509_parent_trace(
                child, parent, top, path_cnt, "signature",
                0, mbedtls_x509_crt_check_key_usage(parent, MBEDTLS_X509_KU_KEY_CERT_SIGN),
                1, ret, -1);
        }

#if defined(MBEDTLS_ECP_RESTARTABLE)
        if (rs_ctx != NULL && ret == MBEDTLS_ERR_ECP_IN_PROGRESS) {
            /* save state */
            rs_ctx->parent = parent;
            rs_ctx->fallback_parent = fallback_parent;
            rs_ctx->fallback_signature_is_good = fallback_signature_is_good;

            return ret;
        }
#else
        (void) ret;
#endif

        signature_is_good = ret == 0;
        if (top && !signature_is_good) {
            continue;
        }

#if defined(MBEDTLS_HAVE_TIME_DATE)
        /* optional time check */
        if (x509_name_cmp(&child->issuer, &parent->subject) == 0) {
            int parent_time_ok =
                mbedtls_x509_time_cmp(&parent->valid_to, now) >= 0 &&
                mbedtls_x509_time_cmp(&parent->valid_from, now) <= 0;
            uefi_x509_parent_trace(
                child, parent, top, path_cnt, "time",
                0, mbedtls_x509_crt_check_key_usage(parent, MBEDTLS_X509_KU_KEY_CERT_SIGN),
                1, ret, parent_time_ok);
        }
        if (mbedtls_x509_time_cmp(&parent->valid_to, now) < 0 ||    /* past */
            mbedtls_x509_time_cmp(&parent->valid_from, now) > 0) {  /* future */
            if (fallback_parent == NULL) {
                fallback_parent = parent;
                fallback_signature_is_good = signature_is_good;
            }

            continue;
        }
#else
        ((void) now);
#endif

        if (x509_name_cmp(&child->issuer, &parent->subject) == 0) {
            uefi_x509_parent_trace(
                child, parent, top, path_cnt, "selected",
                0, mbedtls_x509_crt_check_key_usage(parent, MBEDTLS_X509_KU_KEY_CERT_SIGN),
                1, ret, 1);
        }
        *r_parent = parent;
        *r_signature_is_good = signature_is_good;

        break;
    }"""
 
if old_parent_loop in text:
    text = text.replace(old_parent_loop, new_parent_loop, 1)
elif new_parent_loop not in text:
    raise SystemExit(f"{x509}: expected trusted-parent search loop not found; refusing patch")


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

if text.count("static void uefi_x509_parent_trace(") != 1:
    raise SystemExit(f"{x509}: parent-trace helper count is not exactly one; refusing patched source")

x509.write_text(text)

print("Mbed TLS TLS and X.509 verification checkpoints installed (or already present).")
PY
