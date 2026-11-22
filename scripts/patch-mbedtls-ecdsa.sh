#!/usr/bin/env bash
set -euo pipefail

SRC="${1:?usage: patch-mbedtls-ecdsa.sh MbedTLS-source-directory}"
TF="$SRC/tf-psa-crypto"

python3 - "$TF/extras/pk_wrap.c" "$TF/core/psa_crypto.c" \
  "$TF/drivers/builtin/src/psa_crypto_ecp.c" \
  "$TF/drivers/builtin/src/ecdsa.c" \
  "$TF/drivers/builtin/src/ecp.c" <<'PY'
from pathlib import Path
import sys

pk_wrap, psa_crypto, psa_ecp, ecdsa, ecp = map(Path, sys.argv[1:])


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


def patch_segment(path: Path, start: str, end: str, replacements) -> None:
    text = insert_declaration(path)
    start_pos = text.find(start)
    end_pos = text.find(end, start_pos + len(start)) if start_pos >= 0 else -1
    if start_pos < 0 or end_pos < 0:
        raise SystemExit(f"{path}: expected function boundaries not found; refusing patch")

    segment = text[start_pos:end_pos]
    for old, new, description in replacements:
        if old in segment:
            segment = segment.replace(old, new, 1)
        elif new not in segment:
            raise SystemExit(f"{path}: expected {description} not found; refusing patch")

    text = text[:start_pos] + segment + text[end_pos:]
    path.write_text(text)


patch_segment(
    pk_wrap,
    "static int ecdsa_verify_psa(",
    "static int ecdsa_opaque_verify_wrap(",
    [
        (
            "    psa_status_t status;\n\n    if (curve == 0) {",
            "    psa_status_t status;\n\n"
            "    uefi_browser_tls_log(78, (int) curve_bits);\n"
            "    if (curve == 0) {",
            "ECDSA PK wrapper entry",
        ),
        (
            "    status = psa_import_key(&attributes, key, key_len, &key_id);\n",
            "    status = psa_import_key(&attributes, key, key_len, &key_id);\n"
            "    uefi_browser_tls_log(79, (int) status);\n",
            "PSA public-key import",
        ),
        (
            "    ret = mbedtls_ecdsa_der_to_raw(curve_bits, p, sig_len, extracted_sig,\n"
            "                                   sizeof(extracted_sig), &converted_sig_len);\n",
            "    ret = mbedtls_ecdsa_der_to_raw(curve_bits, p, sig_len, extracted_sig,\n"
            "                                   sizeof(extracted_sig), &converted_sig_len);\n"
            "    uefi_browser_tls_log(80, ret);\n",
            "ECDSA DER-to-raw conversion",
        ),
        (
            "    status = psa_verify_hash(key_id, psa_sig_md, hash, hash_len,\n"
            "                             extracted_sig, signature_len);\n",
            "    uefi_browser_tls_log(81, (int) signature_len);\n"
            "    status = psa_verify_hash(key_id, psa_sig_md, hash, hash_len,\n"
            "                             extracted_sig, signature_len);\n"
            "    uefi_browser_tls_log(82, (int) status);\n",
            "PSA ECDSA verify call",
        ),
        (
            "cleanup:\n    status = psa_destroy_key(key_id);",
            "cleanup:\n"
            "    uefi_browser_tls_log(83, 0);\n"
            "    status = psa_destroy_key(key_id);\n"
            "    uefi_browser_tls_log(84, (int) status);",
            "PSA key destruction",
        ),
    ],
)

patch_segment(
    psa_crypto,
    "static psa_status_t psa_verify_internal(",
    "psa_status_t psa_sign_message_builtin(",
    [
        (
            "    psa_key_slot_t *slot;\n",
            "    psa_key_slot_t *slot;\n\n"
            "    uefi_browser_tls_log(85, input_is_message);\n",
            "PSA verify internal entry",
        ),
        (
            "    } else {\n"
            "        status = psa_driver_wrapper_verify_hash(\n"
            "            &slot->attr, slot->key.data, slot->key.bytes,\n"
            "            alg, input, input_length,\n"
            "            signature, signature_length);\n"
            "    }",
            "    } else {\n"
            "        uefi_browser_tls_log(86, (int) alg);\n"
            "        status = psa_driver_wrapper_verify_hash(\n"
            "            &slot->attr, slot->key.data, slot->key.bytes,\n"
            "            alg, input, input_length,\n"
            "            signature, signature_length);\n"
            "        uefi_browser_tls_log(87, (int) status);\n"
            "    }",
            "PSA verify_hash driver dispatch",
        ),
    ],
)

patch_segment(
    psa_crypto,
    "psa_status_t psa_verify_hash_builtin(",
    "psa_status_t psa_verify_hash(",
    [
        (
            "            return mbedtls_psa_ecdsa_verify_hash(\n"
            "                attributes,\n"
            "                key_buffer, key_buffer_size,\n"
            "                alg, hash, hash_length,\n"
            "                signature, signature_length);",
            "            uefi_browser_tls_log(88, (int) attributes->bits);\n"
            "            psa_status_t verify_status = mbedtls_psa_ecdsa_verify_hash(\n"
            "                attributes,\n"
            "                key_buffer, key_buffer_size,\n"
            "                alg, hash, hash_length,\n"
            "                signature, signature_length);\n"
            "            uefi_browser_tls_log(89, (int) verify_status);\n"
            "            return verify_status;",
            "built-in ECDSA verification dispatch",
        ),
    ],
)

patch_segment(
    psa_ecp,
    "psa_status_t mbedtls_psa_ecdsa_verify_hash(",
    "#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA)",
    [
        (
            "    mbedtls_mpi r, s;\n\n    (void) alg;",
            "    mbedtls_mpi r, s;\n\n"
            "    uefi_browser_tls_log(90, (int) attributes->bits);\n"
            "    (void) alg;",
            "PSA ECDSA verifier entry",
        ),
        (
            "                                                 &ecp);\n"
            "    if (status != PSA_SUCCESS) {",
            "                                                 &ecp);\n"
            "    uefi_browser_tls_log(91, (int) status);\n"
            "    if (status != PSA_SUCCESS) {",
            "PSA ECP key representation load",
        ),
        (
            "    status = mbedtls_psa_ecp_load_public_part(ecp);\n"
            "    if (status != PSA_SUCCESS) {",
            "    uefi_browser_tls_log(92, 0);\n"
            "    status = mbedtls_psa_ecp_load_public_part(ecp);\n"
            "    uefi_browser_tls_log(93, (int) status);\n"
            "    if (status != PSA_SUCCESS) {",
            "PSA ECP public-point load",
        ),
        (
            "    status = mbedtls_to_psa_error(mbedtls_ecdsa_verify(&ecp->grp, hash,\n"
            "                                                       hash_length, &ecp->Q,\n"
            "                                                       &r, &s));",
            "    uefi_browser_tls_log(94, (int) ecp->grp.pbits);\n"
            "    status = mbedtls_to_psa_error(mbedtls_ecdsa_verify(&ecp->grp, hash,\n"
            "                                                       hash_length, &ecp->Q,\n"
            "                                                       &r, &s));\n"
            "    uefi_browser_tls_log(95, (int) status);",
            "ECDSA arithmetic call",
        ),
    ],
)

patch_segment(
    ecdsa,
    "int mbedtls_ecdsa_verify_restartable(",
    "/*\n * Verify ECDSA signature of hashed message\n */",
    [
        (
            "    mbedtls_mpi *pu1 = &u1, *pu2 = &u2;\n",
            "    mbedtls_mpi *pu1 = &u1, *pu2 = &u2;\n\n"
            "    uefi_browser_tls_log(96, (int) grp->pbits);\n",
            "ECDSA arithmetic entry",
        ),
        (
            "    MBEDTLS_MPI_CHK(derive_mpi(grp, &e, buf, blen));",
            "    MBEDTLS_MPI_CHK(derive_mpi(grp, &e, buf, blen));\n"
            "    uefi_browser_tls_log(97, ret);",
            "ECDSA hash-to-integer reduction",
        ),
        (
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_gcd_modinv_odd(NULL, &s_inv, s, &grp->N));",
            "    uefi_browser_tls_log(98, 0);\n"
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_gcd_modinv_odd(NULL, &s_inv, s, &grp->N));\n"
            "    uefi_browser_tls_log(99, ret);",
            "ECDSA modular inverse",
        ),
        (
            "    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd_restartable(grp,\n"
            "                                                   &R, pu1, &grp->G, pu2, Q, ECDSA_RS_ECP));",
            "    uefi_browser_tls_log(100, 0);\n"
            "    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd_restartable(grp,\n"
            "                                                   &R, pu1, &grp->G, pu2, Q, ECDSA_RS_ECP));\n"
            "    uefi_browser_tls_log(101, ret);",
            "ECDSA EC point linear combination",
        ),
        (
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&R.X, &R.X, &grp->N));",
            "    uefi_browser_tls_log(102, 0);\n"
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&R.X, &R.X, &grp->N));\n"
            "    uefi_browser_tls_log(103, ret);",
            "ECDSA final coordinate reduction",
        ),
    ],
)

patch_segment(
    ecp,
    "int mbedtls_ecp_muladd_restartable(",
    "/*\n * Linear combination\n * NOT constant-time\n */",
    [
        (
            "    mbedtls_mpi tmp[4];\n",
            "    mbedtls_mpi tmp[4];\n\n"
            "    uefi_browser_tls_log(104, (int) grp->pbits);\n",
            "ECP linear-combination entry",
        ),
        (
            "    MBEDTLS_MPI_CHK(mbedtls_ecp_mul_shortcuts(grp, pmP, m, P, rs_ctx));",
            "    MBEDTLS_MPI_CHK(mbedtls_ecp_mul_shortcuts(grp, pmP, m, P, rs_ctx));\n"
            "    uefi_browser_tls_log(105, ret);",
            "first ECP scalar multiplication",
        ),
        (
            "    MBEDTLS_MPI_CHK(mbedtls_ecp_mul_shortcuts(grp, pR,  n, Q, rs_ctx));",
            "    MBEDTLS_MPI_CHK(mbedtls_ecp_mul_shortcuts(grp, pR,  n, Q, rs_ctx));\n"
            "    uefi_browser_tls_log(106, ret);",
            "second ECP scalar multiplication",
        ),
        (
            "    MBEDTLS_MPI_CHK(ecp_add_mixed(grp, pR, pmP, pR, tmp));",
            "    MBEDTLS_MPI_CHK(ecp_add_mixed(grp, pR, pmP, pR, tmp));\n"
            "    uefi_browser_tls_log(107, ret);",
            "ECP mixed point addition",
        ),
        (
            "    MBEDTLS_MPI_CHK(ecp_normalize_jac(grp, pR));",
            "    MBEDTLS_MPI_CHK(ecp_normalize_jac(grp, pR));\n"
            "    uefi_browser_tls_log(108, ret);",
            "ECP projective normalization",
        ),
    ],
)

print("Mbed TLS ECDSA/PSA/ECP checkpoints installed (or already present).")
PY
