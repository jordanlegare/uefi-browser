#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="x86_64-unknown-uefi"
COFF_TARGET="x86_64-w64-mingw32"
VERSION="5.9.4"
SRC="$ROOT/vendor/wolfssl-$VERSION"
BUILD="$ROOT/build/wolfssl-$VERSION"
PREFIX="$ROOT/build/wolfssl-install"
BRIDGE_BUILD="$ROOT/build/uefi-wolfssl-bridge"
PLATFORM_INCLUDE="$ROOT/vendor/wolfssl-bridge/include"
MINGW_INCLUDE="/usr/x86_64-w64-mingw32/include"

if [[ ! -d "$MINGW_INCLUDE" ]]; then
  echo "MinGW-w64 x86-64 headers not found at $MINGW_INCLUDE." >&2
  echo "Install mingw-w64-x86-64-dev or edit MINGW_INCLUDE." >&2
  exit 1
fi

command -v cmake >/dev/null
command -v ninja >/dev/null
command -v clang >/dev/null
command -v llvm-ar >/dev/null
command -v rustup >/dev/null
command -v unzip >/dev/null
rustup target add "$TARGET"

bash "$ROOT/scripts/fetch-wolfssl.sh"

rm -rf "$BUILD" "$PREFIX" "$BRIDGE_BUILD"
mkdir -p "$BRIDGE_BUILD"

# Keep the MinGW x86-64 ABI macros enabled so pointer-sized wolfSSL types
# match the target. WOLFSSL_NOT_WINDOWS_API in user_settings.h disables
# Windows OS APIs while retaining the PE/COFF Windows calling convention.
C_FLAGS="-DNOMINMAX -O2 -ffreestanding -fno-builtin -fshort-wchar -DWOLFSSL_USER_SETTINGS -I$PLATFORM_INCLUDE -isystem $MINGW_INCLUDE"

cmake -S "$SRC" -B "$BUILD" -G Ninja \
  -DCMAKE_SYSTEM_NAME=Generic \
  -DCMAKE_SYSTEM_PROCESSOR=x86_64 \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_C_COMPILER_TARGET="$COFF_TARGET" \
  -DCMAKE_ASM_COMPILER=clang \
  -DCMAKE_ASM_COMPILER_TARGET="$COFF_TARGET" \
  -DCMAKE_ASM_FLAGS="-DNOMINMAX -DWOLFSSL_USER_SETTINGS -I$PLATFORM_INCLUDE -isystem $MINGW_INCLUDE" \
  -DCMAKE_C_FLAGS="$C_FLAGS" \
  -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DBUILD_SHARED_LIBS=OFF \
  -DWOLFSSL_USER_SETTINGS=yes \
  -DWOLFSSL_EXAMPLES=no \
  -DWOLFSSL_CRYPT_TESTS=no

cmake --build "$BUILD" --parallel
cmake --install "$BUILD"
test -s "$PREFIX/lib/libwolfssl.a"

BRIDGE_CFLAGS="-DNOMINMAX -std=c11 -O2 -ffreestanding -fno-builtin -fshort-wchar -DWOLFSSL_USER_SETTINGS -I$PLATFORM_INCLUDE -I$SRC -I$PREFIX/include -isystem $MINGW_INCLUDE"

clang $BRIDGE_CFLAGS --target="$COFF_TARGET" \
  -c "$ROOT/vendor/wolfssl-bridge/uefi_tls.c" \
  -o "$BRIDGE_BUILD/uefi_tls.obj"
clang $BRIDGE_CFLAGS --target="$COFF_TARGET" \
  -c "$ROOT/vendor/wolfssl-bridge/uefi_platform.c" \
  -o "$BRIDGE_BUILD/uefi_platform.obj"
clang $BRIDGE_CFLAGS --target="$COFF_TARGET" \
  -c "$ROOT/vendor/wolfssl-bridge/uefi_date.c" \
  -o "$BRIDGE_BUILD/uefi_date.obj"
clang $BRIDGE_CFLAGS --target="$COFF_TARGET" \
  -c "$ROOT/vendor/wolfssl-bridge/uefi_crt.c" \
  -o "$BRIDGE_BUILD/uefi_crt.obj"

llvm-ar rcs "$BRIDGE_BUILD/libuefi_wolfssl_bridge.a" \
  "$BRIDGE_BUILD/uefi_tls.obj" \
  "$BRIDGE_BUILD/uefi_platform.obj" \
  "$BRIDGE_BUILD/uefi_date.obj" \
  "$BRIDGE_BUILD/uefi_crt.obj"

export UEFI_WOLFSSL_LIB_DIR="$PREFIX/lib"
export UEFI_WOLFSSL_BRIDGE_DIR="$BRIDGE_BUILD"

bash "$ROOT/scripts/update-ca-bundle.sh"
if [[ -f "$ROOT/assets/cacert.pem" ]]; then
  source "$ROOT/scripts/check-ca-bundle.sh"
  FILTERED_CA_BUNDLE="$ROOT/build/cacert-uefi.pem"
  bash "$ROOT/scripts/filter-ca-bundle.sh" "$ROOT/assets/cacert.pem" "$FILTERED_CA_BUNDLE"
  export UEFI_CA_BUNDLE_PATH="$FILTERED_CA_BUNDLE"
else
  echo "CA bundle not found: run scripts/update-ca-bundle.sh to prepare HTTPS trust roots." >&2
  exit 1
fi

cargo build --release --target "$TARGET"

EFI_BINARY="$ROOT/target/$TARGET/release/uefi-browser.efi"
test -s "$EFI_BINARY"
mkdir -p "$ROOT/dist/EFI/BOOT"
install -m 0644 "$EFI_BINARY" "$ROOT/dist/EFI/BOOT/BOOTX64.EFI"

echo "Built standalone EFI application: $EFI_BINARY"
echo "Removable-media path: $ROOT/dist/EFI/BOOT/BOOTX64.EFI"
