#!/usr/bin/env bash
set -euo pipefail

SRC="${1:?usage: patch-mbedtls-ecdsa.sh MbedTLS-source-directory}"
TF="$SRC/tf-psa-crypto"

python3 - "$TF/extras/pk_wrap.c" "$TF/core/psa_crypto.c" \
  "$TF/drivers/builtin/src/psa_crypto_ecp.c" \
  "$TF/drivers/builtin/src/ecdsa.c" \
  "$TF/drivers/builtin/src/ecp.c" \
  "$TF/drivers/builtin/src/bignum.c" <<'PY'
from pathlib import Path
import re
import sys

pk_wrap, psa_crypto, psa_ecp, ecdsa, ecp, bignum = map(Path, sys.argv[1:])


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


def find_matching_brace(text: str, opening_brace: int) -> int:
    """Return the index immediately after the matching closing brace."""
    depth = 0
    for index in range(opening_brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    raise SystemExit("MPI modulo positive-remainder loop has unbalanced braces; refusing patch")


def patch_segment(path: Path, start: str, end: str, replacements) -> None:
    text = insert_declaration(path)
    start_pos = text.find(start)
    end_pos = text.find(end, start_pos + len(start)) if start_pos >= 0 else -1
    if start_pos < 0 or end_pos < 0:
        raise SystemExit(f"{path}: expected function boundaries not found; refusing patch")

    segment = text[start_pos:end_pos]
    for old, new, description in replacements:
        # Check the patched form first: the original text is often still a
        # substring of the replacement, so checking old first duplicates logs.
        if new in segment:
            continue
        # PR-era MPI modulo instrumentation used a for-loop with explicit
        # comparison/subtraction checkpoints instead of the original while.
        if (
            description == "MPI modulo negative correction completion and positive correction entry"
            and "uefi_browser_tls_log(136, 0);" in segment
            and "uefi_browser_tls_log(137, 0);" in segment
            and "for (;;) {" in segment
        ):
            continue
        if old in segment:
            segment = segment.replace(old, new, 1)
        elif (
            start == "int mbedtls_mpi_mod_mpi("
            and description == "MPI modulo positive correction entry"
            and "for (;;) {" in segment
        ):
            # Older diagnostic builds rewrote the positive-remainder while
            # loop as for (;;) with an explicit comparison/break. Keep that
            # loop intact and put the new one-shot marker before it.
            loop_pos = segment.find("for (;;) {")
            if "uefi_browser_tls_log(169," not in segment:
                segment = (
                    segment[:loop_pos]
                    + "    uefi_browser_tls_log(169, 0);\n"
                    + segment[loop_pos:]
                )
        elif (
            start == "int mbedtls_mpi_mod_mpi("
            and description == "MPI remainder and modulus limb counts"
            and "for (;;) {" in segment
        ):
            # Older builds may have rewritten the correction loop as for (;;).
            # Place the limb-size report immediately before that loop.
            if "uefi_browser_tls_log(176," not in segment:
                loop_pos = segment.find("for (;;) {")
                segment = (
                    segment[:loop_pos]
                    + "    uefi_browser_tls_log(176, (int) R->n);\n"
                    + "    uefi_browser_tls_log(177, (int) B->n);\n"
                    + segment[loop_pos:]
                )
        elif (
            start == "int mbedtls_mpi_mod_mpi("
            and description == "MPI modulo positive correction completion"
            and "for (;;) {" in segment
        ):
            # Locate the loop's closing brace structurally so stage 170
            # remains outside the arithmetic loop.
            loop_pos = segment.find("for (;;) {")
            opening_brace = segment.find("{", loop_pos)
            loop_end = find_matching_brace(segment, opening_brace)
            if "uefi_browser_tls_log(170," not in segment[loop_end:]:
                segment = (
                    segment[:loop_end]
                    + "\n    uefi_browser_tls_log(170, 0);"
                    + segment[loop_end:]
                )
        else:
            raise SystemExit(f"{path}: expected {description} not found; refusing patch")

    # Clean up duplicate adjacent checkpoints left by earlier non-idempotent
    # runs of this patcher. Do not alter any arithmetic statements.
    if start == "int mbedtls_mpi_mod_mpi(":
        for stage in (134, 135):
            line = rf"(?m)^(\s*uefi_browser_tls_log\({stage}, [^\n]*\);\n)(?:\s*uefi_browser_tls_log\({stage}, [^\n]*\);\n)+"
            segment = re.sub(line, r"\1", segment)

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
            "    mbedtls_mpi e, s_inv, u1, u2;\n",
            "    mbedtls_mpi e, s_inv, u1, u2, mod_tmp;\n",
            "ECDSA temporary modulo MPI declaration",
        ),
        (
            "    mbedtls_mpi_init(&u1); mbedtls_mpi_init(&u2);\n",
            "    mbedtls_mpi_init(&u1); mbedtls_mpi_init(&u2);\n"
            "    mbedtls_mpi_init(&mod_tmp);\n",
            "ECDSA temporary modulo MPI initialization",
        ),
        (
            "    mbedtls_mpi_free(&u1); mbedtls_mpi_free(&u2);\n",
            "    mbedtls_mpi_free(&u1); mbedtls_mpi_free(&u2);\n"
            "    mbedtls_mpi_free(&mod_tmp);\n",
            "ECDSA temporary modulo MPI cleanup",
        ),
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
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(pu1, &e, &s_inv));",
            "    uefi_browser_tls_log(110, 0);\n"
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(pu1, &e, &s_inv));\n"
            "    uefi_browser_tls_log(111, ret);",
            "ECDSA u1 multiplication",
        ),
        (
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(pu1, pu1, &grp->N));",
            "    uefi_browser_tls_log(112, 0);\n"
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&mod_tmp, pu1, &grp->N));\n"
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(pu1, &mod_tmp));\n"
            "    uefi_browser_tls_log(113, ret);",
            "ECDSA u1 modular reduction without MPI aliasing",
        ),
        (
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(pu2, r, &s_inv));",
            "    uefi_browser_tls_log(114, 0);\n"
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(pu2, r, &s_inv));\n"
            "    uefi_browser_tls_log(115, ret);",
            "ECDSA u2 multiplication",
        ),
        (
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(pu2, pu2, &grp->N));",
            "    uefi_browser_tls_log(116, 0);\n"
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&mod_tmp, pu2, &grp->N));\n"
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(pu2, &mod_tmp));\n"
            "    uefi_browser_tls_log(117, ret);",
            "ECDSA u2 modular reduction without MPI aliasing",
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


patch_segment(
    ecp,
    "static int ecp_mul_restartable_internal(",
    "/*\n * Restartable multiplication R = m * P\n */",
    [
        (
            "        MBEDTLS_MPI_CHK(mbedtls_ecp_check_privkey(grp, m));\n"
            "        MBEDTLS_MPI_CHK(mbedtls_ecp_check_pubkey(grp, P));",
            "        MBEDTLS_MPI_CHK(mbedtls_ecp_check_privkey(grp, m));\n"
            "        uefi_browser_tls_log(148, 0);\n"
            "        MBEDTLS_MPI_CHK(mbedtls_ecp_check_pubkey(grp, P));\n"
            "        uefi_browser_tls_log(149, ret);",
            "ECP scalar input validation",
        ),
        (
            "        MBEDTLS_MPI_CHK(ecp_mul_comb(grp, R, m, P, f_rng, p_rng, rs_ctx));",
            "        uefi_browser_tls_log(150, (int) grp->pbits);\n"
            "        MBEDTLS_MPI_CHK(ecp_mul_comb(grp, R, m, P, f_rng, p_rng, rs_ctx));\n"
            "        uefi_browser_tls_log(151, ret);",
            "ECP comb multiplication",
        ),
    ],
)

patch_segment(
    ecp,
    "static int ecp_mul_comb(",
    "#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */",
    [
        (
            "    ECP_RS_ENTER(rsm);",
            "    ECP_RS_ENTER(rsm);\n"
            "    uefi_browser_tls_log(152, (int) grp->pbits);",
            "ECP comb engine entry",
        ),
        (
            "        MBEDTLS_MPI_CHK(ecp_precompute_comb(grp, T, P, w, d, rs_ctx));",
            "        uefi_browser_tls_log(153, (int) T_size);\n"
            "        MBEDTLS_MPI_CHK(ecp_precompute_comb(grp, T, P, w, d, rs_ctx));\n"
            "        uefi_browser_tls_log(154, ret);",
            "ECP precomputed table generation",
        ),
        (
            "    MBEDTLS_MPI_CHK(ecp_mul_comb_after_precomp(grp, R, m,",
            "    uefi_browser_tls_log(155, (int) T_size);\n"
            "    MBEDTLS_MPI_CHK(ecp_mul_comb_after_precomp(grp, R, m,",
            "ECP comb scalar evaluation entry",
        ),
    ],
)

patch_segment(
    ecp,
    "static int ecp_mul_comb_after_precomp(",
    "/*\n * Pick window size based on curve size",
    [
        (
            "    MBEDTLS_MPI_CHK(ecp_comb_recode_scalar(grp, m, k, d, w,\n"
            "                                           &parity_trick));",
            "    uefi_browser_tls_log(156, (int) d);\n"
            "    MBEDTLS_MPI_CHK(ecp_comb_recode_scalar(grp, m, k, d, w,\n"
            "                                           &parity_trick));\n"
            "    uefi_browser_tls_log(157, ret);",
            "ECP scalar recoding",
        ),
        (
            "    MBEDTLS_MPI_CHK(ecp_mul_comb_core(grp, RR, T, T_size, k, d,\n"
            "                                      f_rng, p_rng, rs_ctx));",
            "    uefi_browser_tls_log(158, 0);\n"
            "    MBEDTLS_MPI_CHK(ecp_mul_comb_core(grp, RR, T, T_size, k, d,\n"
            "                                      f_rng, p_rng, rs_ctx));\n"
            "    uefi_browser_tls_log(159, ret);",
            "ECP comb core scalar multiplication",
        ),
        (
            "    MBEDTLS_MPI_CHK(ecp_normalize_jac(grp, RR));",
            "    uefi_browser_tls_log(160, 0);\n"
            "    MBEDTLS_MPI_CHK(ecp_normalize_jac(grp, RR));\n"
            "    uefi_browser_tls_log(161, ret);",
            "ECP scalar result normalization",
        ),
    ],
)

patch_segment(
    ecp,
    "int mbedtls_ecp_muladd_restartable(",
    "/*\n * Linear combination\n * NOT constant-time",
    [
        (
            "    MBEDTLS_MPI_CHK(mbedtls_ecp_mul_shortcuts(grp, pmP, m, P, rs_ctx));",
            "    uefi_browser_tls_log(140, 0);\n"
            "    MBEDTLS_MPI_CHK(mbedtls_ecp_mul_shortcuts(grp, pmP, m, P, rs_ctx));\n"
            "    uefi_browser_tls_log(141, ret);",
            "first ECP scalar multiplication",
        ),
        (
            "    MBEDTLS_MPI_CHK(mbedtls_ecp_mul_shortcuts(grp, pR,  n, Q, rs_ctx));",
            "    uefi_browser_tls_log(142, 0);\n"
            "    MBEDTLS_MPI_CHK(mbedtls_ecp_mul_shortcuts(grp, pR,  n, Q, rs_ctx));\n"
            "    uefi_browser_tls_log(143, ret);",
            "second ECP scalar multiplication",
        ),
        (
            "    MBEDTLS_MPI_CHK(ecp_add_mixed(grp, pR, pmP, pR, tmp));",
            "    uefi_browser_tls_log(144, 0);\n"
            "    MBEDTLS_MPI_CHK(ecp_add_mixed(grp, pR, pmP, pR, tmp));\n"
            "    uefi_browser_tls_log(145, ret);",
            "ECP point addition",
        ),
        (
            "    MBEDTLS_MPI_CHK(ecp_normalize_jac(grp, pR));",
            "    uefi_browser_tls_log(146, 0);\n"
            "    MBEDTLS_MPI_CHK(ecp_normalize_jac(grp, pR));\n"
            "    uefi_browser_tls_log(147, ret);",
            "ECP final point normalization",
        ),
    ],
)

# Keep MPI modulo correction bounded. Division must return a remainder whose
# magnitude is smaller than the positive modulus. A negative remainder needs
# at most one addition of B; any other out-of-range result is an arithmetic
# invariant failure and must abort verification instead of looping forever.
def patch_mpi_modulo_guard() -> None:
    text = insert_declaration(bignum)
    start = text.find("int mbedtls_mpi_mod_mpi(")
    end = text.find("/*\n * Modulo: r = A mod b", start)
    if start < 0 or end < 0:
        raise SystemExit(f"{bignum}: MPI modulo function boundaries not found; refusing patch")

    segment = text[start:end]
    segment = segment.replace("    size_t correction_iterations = 0;\n", "")
    div_call = "    MBEDTLS_MPI_CHK(mbedtls_mpi_div_mpi(NULL, R, A, B));"
    div_pos = segment.find(div_call)
    cleanup_pos = segment.find("\ncleanup:", div_pos)
    if div_pos < 0 or cleanup_pos < 0:
        raise SystemExit(f"{bignum}: MPI modulo division/cleanup boundary not found; refusing patch")

    guard = (
        "\n"
        "    uefi_browser_tls_log(167, (int) R->n);\n"
        "    /* UEFI: fail closed if division violates the MPI remainder invariant. */\n"
        "    if (mbedtls_mpi_cmp_int(R, 0) < 0) {\n"
        "        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(R, R, B));\n"
        "    }\n"
        "    if (mbedtls_mpi_cmp_int(R, 0) < 0 ||\n"
        "        mbedtls_mpi_cmp_mpi(R, B) >= 0) {\n"
        "        ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;\n"
        "        goto cleanup;\n"
        "    }\n"
        "    uefi_browser_tls_log(168, 0);\n"
    )

    if "/* UEFI: fail closed if division violates the MPI remainder invariant. */" in segment:
        # The guard is already present. Still ensure stage 166 remains before
        # the division call when re-running against an existing vendor tree.
        pass
    else:
        after_div = div_pos + len(div_call)
        segment = segment[:after_div] + guard + segment[cleanup_pos:]

    if "uefi_browser_tls_log(166," not in segment:
        div_pos = segment.find(div_call)
        segment = (
            segment[:div_pos]
            + "    uefi_browser_tls_log(166, (int) A->n);\n"
            + segment[div_pos:]
        )

    text = text[:start] + segment + text[end:]
    bignum.write_text(text)


patch_mpi_modulo_guard()

patch_segment(
    bignum,
    "int mbedtls_mpi_div_mpi(",
    "/*\n * Division by int:",
    [
        (
            "    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;\n",
            "    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;\n"
            "    uefi_browser_tls_log(171, (int) A->n);\n",
            "MPI division entry",
        ),
        (
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&Y, biL * (n - t)));\n",
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&Y, biL * (n - t)));\n"
            "    uefi_browser_tls_log(172, (int) (n - t));",
            "MPI division aligned-divisor boundary",
        ),
        (
            "        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&X, &X, &Y));\n"
            "    }\n"
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&Y, biL * (n - t)));",
            "        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&X, &X, &Y));\n"
            "    }\n"
            "    uefi_browser_tls_log(173, (int) X.n);\n"
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&Y, biL * (n - t)));",
            "MPI division leading quotient-digit completion",
        ),
        (
            "    for (i = n; i > t; i--) {",
            "    uefi_browser_tls_log(174, (int) (n - t));\n"
            "    for (i = n; i > t; i--) {",
            "MPI division quotient-digit loop entry",
        ),
        (
            "    if (R != NULL) {\n"
            "        MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&X, k));",
            "    uefi_browser_tls_log(175, 0);\n"
            "    if (R != NULL) {\n"
            "        MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&X, k));",
            "MPI division quotient-digit loop completion",
        ),
    ],
)

# Keep the underlying MPI arithmetic intact, but remove the temporary
# division/modulo trace calls from the vendored Mbed TLS source. This also
# cleans vendor trees that were patched by earlier diagnostic builds.
mpi_source = bignum.read_text()
mpi_source = re.sub(
    r"(?m)^[ \t]*uefi_browser_tls_log[(](?:12[0-9]|13[0-9]|16[2-5]),[^\n]*[)];\n",
    "",
    mpi_source,
)
bignum.write_text(mpi_source)

print("Mbed TLS ECDSA/PSA/ECP checkpoints installed (or already present).")
PY
