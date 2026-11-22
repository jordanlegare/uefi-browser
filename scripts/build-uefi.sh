#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="x86_64-unknown-uefi"
COFF_TARGET="x86_64-pc-win32-coff"
VERSION="4.3.0"
SRC="$ROOT/vendor/mbedtls-$VERSION"
BUILD="$ROOT/build/mbedtls-$VERSION"
PREFIX="$ROOT/build/mbedtls-install"
BRIDGE_BUILD="$ROOT/build/uefi-mbedtls-bridge"
PLATFORM_INCLUDE="$ROOT/vendor/mbedtls-bridge/include"
USER_CONFIG_DEFINE='-DMBEDTLS_USER_CONFIG_FILE=\"uefi_mbedtls_config.h\"'

"$ROOT/scripts/fetch-mbedtls.sh"

command -v cmake >/dev/null
command -v ninja >/dev/null
command -v clang >/dev/null
command -v llvm-ar >/dev/null
rustup target add "$TARGET"

C_FLAGS="-ffreestanding -fno-builtin -fshort-wchar -I$PLATFORM_INCLUDE $USER_CONFIG_DEFINE"

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
  "-I$PLATFORM_INCLUDE"
  "-I$SRC/include"
  "$USER_CONFIG_DEFINE"
)

clang "${COMMON_CFLAGS[@]}" \
  -c "$ROOT/vendor/mbedtls-bridge/uefi_tls.c" \
  -o "$BRIDGE_BUILD/uefi_tls.obj"
clang "${COMMON_CFLAGS[@]}" \
  -c "$ROOT/vendor/mbedtls-bridge/uefi_platform.c" \
  -o "$BRIDGE_BUILD/uefi_platform.obj"

llvm-ar rcs "$BRIDGE_BUILD/libuefi_mbedtls_bridge.a" \
  "$BRIDGE_BUILD/uefi_tls.obj" \
  "$BRIDGE_BUILD/uefi_platform.obj"

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
