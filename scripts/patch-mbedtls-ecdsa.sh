#!/usr/bin/env bash
set -euo pipefail

SRC="\${1:?usage: patch-mbedtls-ecdsa.sh MbedTLS-source-directory}"
TF="$SRC/tf-psa-crypto"

python3 - "$TF" <<'PY'
from pathlib import Path
import re
import sys

tf = Path(sys.argv[1])
ecdsa = tf / "drivers/builtin/src/ecdsa.c"
bignum = tf / "drivers/builtin/src/bignum.c"

# Remove instrumentation left by earlier diagnostic builds. No callback
# declarations or trace calls are permitted in the patched TF-PSA sources.
for path in tf.rglob("*.c"):
    source = path.read_text()
    source = re.sub(
        r"(?m)^[ \t]*extern void uefi_browser_tls_log\([^;\n]*\);[ \t]*\n?",
        "",
        source,
    )
    source = re.sub(
        r"(?m)^[ \t]*uefi_browser_tls_log\([^;\n]*\);[ \t]*\n?",
        "",
        source,
    )
    path.write_text(source)


def patch_function(path: Path, start: str, end: str, replacements) -> None:
    source = path.read_text()
    start_pos = source.find(start)
    end_pos = source.find(end, start_pos + len(start)) if start_pos >= 0 else -1
    if start_pos < 0 or end_pos < 0:
        raise SystemExit(f"{path}: expected function boundaries not found; refusing patch")

    segment = source[start_pos:end_pos]
    for old, new, description in replacements:
        if new in segment:
            continue
        if old not in segment:
            raise SystemExit(f"{path}: expected {description} not found; refusing patch")
        segment = segment.replace(old, new, 1)

    path.write_text(source[:start_pos] + segment + source[end_pos:])


# ECDSA needs a separate MPI destination for in-place modular reductions.
# Preserve this arithmetic fix while keeping the verification path silent.
patch_function(
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
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(pu1, pu1, &grp->N));",
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&mod_tmp, pu1, &grp->N));\n"
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(pu1, &mod_tmp));",
            "ECDSA u1 modular reduction without MPI aliasing",
        ),
        (
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(pu2, pu2, &grp->N));",
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&mod_tmp, pu2, &grp->N));\n"
            "    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(pu2, &mod_tmp));",
            "ECDSA u2 modular reduction without MPI aliasing",
        ),
    ],
)


# Keep MPI modulo correction bounded. Division must produce a remainder
# strictly smaller than the positive modulus. Correct a negative remainder
# once, then fail closed on any other violation instead of looping forever.
source = bignum.read_text()
start = source.find("int mbedtls_mpi_mod_mpi(")
end = source.find("/*\n * Modulo: r = A mod b", start)
if start < 0 or end < 0:
    raise SystemExit(f"{bignum}: MPI modulo function boundaries not found; refusing patch")

segment = source[start:end]
segment = segment.replace("    size_t correction_iterations = 0;\n", "")
div_call = "    MBEDTLS_MPI_CHK(mbedtls_mpi_div_mpi(NULL, R, A, B));"
div_pos = segment.find(div_call)
if div_pos < 0:
    raise SystemExit(f"{bignum}: MPI modulo division call not found; refusing patch")

guard = (
    "\n"
    "    /* UEFI: fail closed if division violates the MPI remainder invariant. */\n"
    "    if (mbedtls_mpi_cmp_int(R, 0) < 0) {\n"
    "        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(R, R, B));\n"
    "    }\n"
    "    if (mbedtls_mpi_cmp_int(R, 0) < 0 ||\n"
    "        mbedtls_mpi_cmp_mpi(R, B) >= 0) {\n"
    "        ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;\n"
    "        goto cleanup;\n"
    "    }\n"
)

marker = "/* UEFI: fail closed if division violates the MPI remainder invariant. */"
if marker in segment:
    required = [
        "mbedtls_mpi_add_mpi(R, R, B)",
        "mbedtls_mpi_cmp_mpi(R, B) >= 0",
        "ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;",
        "goto cleanup;",
    ]
    if not all(item in segment for item in required):
        raise SystemExit(f"{bignum}: existing MPI remainder guard is incomplete")
else:
    after_div = div_pos + len(div_call)
    segment = segment[:after_div] + guard + segment[after_div:]

bignum.write_text(source[:start] + segment + source[end:])

# Assert that no diagnostic callback survived the cleanup or was reintroduced.
for path in tf.rglob("*.c"):
    if "uefi_browser_tls_log" in path.read_text():
        raise SystemExit(f"{path}: TLS diagnostic callback remains after cleanup")
PY
