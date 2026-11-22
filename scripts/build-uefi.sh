#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="x86_64-unknown-uefi"
COFF_TARGET="x86_64-w64-windows-gnu"
VERSION="4.3.0"
SRC="$ROOT/vendor/mbedtls-$VERSION"
BUILD="$ROOT/build/mbedtls-$VERSION"
PREFIX="$ROOT/build/mbedtls-install"
BRIDGE_BUILD="$ROOT/build/uefi-mbedtls-bridge"
PLATFORM_INCLUDE="$ROOT/vendor/mbedtls-bridge/include"
MINGW_INCLUDE="${MINGW_INCLUDE:-/usr/x86_64-w64-mingw32/include}"
if [[ ! -d "$MINGW_INCLUDE" ]]; then
  echo "MinGW-w64 C headers not found at $MINGW_INCLUDE." >&2
  echo "Install mingw-w64-x86-64-dev or set MINGW_INCLUDE." >&2
  exit 1
fi

# Mbed TLS 4.x and its TF-PSA-Crypto subproject have distinct user-config hooks.
USER_CONFIG_DEFINE='-DMBEDTLS_USER_CONFIG_FILE=\"uefi_mbedtls_config.h\"'
PSA_USER_CONFIG_DEFINE='-DTF_PSA_CRYPTO_USER_CONFIG_FILE=\"uefi_tf_psa_config.h\"'
BRIDGE_USER_CONFIG_DEFINE='-DMBEDTLS_USER_CONFIG_FILE="uefi_mbedtls_config.h"'
BRIDGE_PSA_USER_CONFIG_DEFINE='-DTF_PSA_CRYPTO_USER_CONFIG_FILE="uefi_tf_psa_config.h"'

bash "$ROOT/scripts/fetch-mbedtls.sh"

# Remove the upstream MinGW formatter override: it bypasses the platform hooks
# and adds native MinGW snprintf dependencies to the EFI image. This patch must
# be idempotent because a failed build can be rerun against the same extracted
# (and already-patched) source directory.
DEBUG_SOURCE="$SRC/library/debug.c"
MINGW_MARKER_COUNT="$(grep -Fc 'Temporary hack: on MingW' "$DEBUG_SOURCE" || true)"
MINGW_GUARD_COUNT="$(grep -Fxc '#if defined(__MINGW32__)' "$DEBUG_SOURCE" || true)"
MINGW_OVERRIDE_COUNT="$(grep -Ec '^#(undef|define) mbedtls_(v)?snprintf([[:space:]]|$)' "$DEBUG_SOURCE" || true)"

if [[ "$MINGW_MARKER_COUNT" -eq 1 && "$MINGW_GUARD_COUNT" -eq 1 && "$MINGW_OVERRIDE_COUNT" -eq 4 ]]; then
  # Verify all four expected directives before removing the bounded block.
  for directive in \
    '#undef mbedtls_snprintf' \
    '#define mbedtls_snprintf snprintf' \
    '#undef mbedtls_vsnprintf' \
    '#define mbedtls_vsnprintf vsnprintf'; do
    if [[ "$(grep -Fxc "$directive" "$DEBUG_SOURCE" || true)" -ne 1 ]]; then
      echo "Unexpected Mbed TLS debug.c MinGW formatter directives; refusing an unsafe patch." >&2
      exit 1
    fi
  done

  sed -i '/^\/\* Temporary hack: on MingW, do not honor the platform.h configuration$/,/^#endif$/d' "$DEBUG_SOURCE"
  if grep -Eq '__MINGW32__|^#(undef|define) mbedtls_(v)?snprintf([[:space:]]|$)' "$DEBUG_SOURCE"; then
    echo "Mbed TLS debug.c MinGW formatter override remains after patching." >&2
    exit 1
  fi
elif [[ "$MINGW_MARKER_COUNT" -eq 0 && "$MINGW_GUARD_COUNT" -eq 0 && "$MINGW_OVERRIDE_COUNT" -eq 0 ]]; then
  echo "Mbed TLS debug.c MinGW formatter override is already absent; skipping patch."
else
  echo "Unexpected Mbed TLS debug.c MinGW formatter block; refusing an unsafe patch." >&2
  exit 1
fi

command -v cmake >/dev/null
command -v ninja >/dev/null
command -v clang >/dev/null
command -v llvm-ar >/dev/null
rustup target add "$TARGET"

C_FLAGS="-ffreestanding -fno-builtin -fshort-wchar -DEFIX64 -DMBEDTLS_TEST_SW_INET_PTON -I$PLATFORM_INCLUDE -isystem $MINGW_INCLUDE $USER_CONFIG_DEFINE $PSA_USER_CONFIG_DEFINE"

cmake -S "$SRC" -B "$BUILD" -G Ninja \
  -DCMAKE_SYSTEM_NAME=Generic \
  -DCMAKE_SYSTEM_PROCESSOR=x86_64 \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_C_COMPILER_TARGET="$COFF_TARGET" \
  -DCMAKE_C_FLAGS="$C_FLAGS" \
  -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DUSE_SHARED_MBEDTLS_LIBRARY=OFF \
  -DUSE_STATIC_MBEDTLS_LIBRARY=ON \
  -DENABLE_PROGRAMS=OFF \
  -DENABLE_TESTING=OFF

cmake --build "$BUILD" --parallel
cmake --install "$BUILD"

mkdir -p "$BRIDGE_BUILD"
COMMON_CFLAGS=(
  "--target=$COFF_TARGET"
  -std=c11
  -ffreestanding
  -fno-builtin
  -fshort-wchar
  -DEFIX64
  -DMBEDTLS_TEST_SW_INET_PTON
  "-I$PLATFORM_INCLUDE"
  "-I$SRC/include"
  "-I$SRC/tf-psa-crypto/include"
  "-I$PREFIX/include"
  "-isystem"
  "$MINGW_INCLUDE"
  "$BRIDGE_USER_CONFIG_DEFINE"
  "$BRIDGE_PSA_USER_CONFIG_DEFINE"
)

clang "${COMMON_CFLAGS[@]}" \
  -c "$ROOT/vendor/mbedtls-bridge/uefi_tls.c" \
  -o "$BRIDGE_BUILD/uefi_tls.obj"
clang "${COMMON_CFLAGS[@]}" \
  -c "$ROOT/vendor/mbedtls-bridge/uefi_platform.c" \
  -o "$BRIDGE_BUILD/uefi_platform.obj"
clang "${COMMON_CFLAGS[@]}" \
  -c "$ROOT/vendor/mbedtls-bridge/uefi_crt.c" \
  -o "$BRIDGE_BUILD/uefi_crt.obj"

llvm-ar rcs "$BRIDGE_BUILD/libuefi_mbedtls_bridge.a" \
  "$BRIDGE_BUILD/uefi_tls.obj" \
  "$BRIDGE_BUILD/uefi_platform.obj" \
  "$BRIDGE_BUILD/uefi_crt.obj"

export UEFI_MBEDTLS_LIB_DIR="$PREFIX/lib"
export UEFI_MBEDTLS_BRIDGE_DIR="$BRIDGE_BUILD"

if [[ -f "$ROOT/assets/cacert.pem" ]]; then
  export UEFI_CA_BUNDLE_PATH="$ROOT/assets/cacert.pem"
else
  echo "CA bundle not found: run scripts/update-ca-bundle.sh to prepare HTTPS trust roots." >&2
fi

cargo build --release --target "$TARGET"

EFI_BINARY="$ROOT/target/$TARGET/release/uefi-browser.efi"
test -s "$EFI_BINARY"
mkdir -p "$ROOT/dist/EFI/BOOT"
install -m 0644 "$EFI_BINARY" "$ROOT/dist/EFI/BOOT/BOOTX64.EFI"

echo "Built standalone EFI application: $EFI_BINARY"
echo "Removable-media path: $ROOT/dist/EFI/BOOT/BOOTX64.EFI"
