#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="x86_64-unknown-uefi"
COFF_TARGET="x86_64-w64-mingw32"
VERSION="5.9.4"
SRC="$ROOT/vendor/wolfssl-$VERSION"
PREFIX="$ROOT/build/wolfssl-install"
BRIDGE_BUILD="$ROOT/build/uefi-wolfssl-bridge"
PLATFORM_INCLUDE="$ROOT/vendor/wolfssl-bridge/include"
MINGW_INCLUDE="/usr/x86_64-w64-mingw32/include"

if [[ ! -d "$MINGW_INCLUDE" ]]; then
  echo "MinGW-w64 x86-64 headers not found at $MINGW_INCLUDE." >&2
  echo "Install mingw-w64-x86-64-dev or edit MINGW_INCLUDE." >&2
  exit 1
fi

command -v clang >/dev/null
command -v llvm-ar >/dev/null
command -v llvm-ranlib >/dev/null
command -v make >/dev/null
command -v unzip >/dev/null
rustup target add "$TARGET"

bash "$ROOT/scripts/fetch-wolfssl.sh"

rm -rf "$PREFIX" "$BRIDGE_BUILD"
mkdir -p "$BRIDGE_BUILD"

COMMON_CFLAGS="-O2 -ffreestanding -fno-builtin -fshort-wchar -DWOLFSSL_USER_SETTINGS -I$PLATFORM_INCLUDE -isystem $MINGW_INCLUDE"

(
  cd "$SRC"
  CC="clang --target=$COFF_TARGET" \
  AR=llvm-ar \
  RANLIB=llvm-ranlib \
  CFLAGS="$COMMON_CFLAGS" \
  ./configure \
    --host="$COFF_TARGET" \
    --prefix="$PREFIX" \
    --enable-usersettings \
    --disable-shared \
    --enable-static \
    --disable-examples \
    --disable-crypttests \
    --disable-benchmark
  make --jobs="$(nproc)"
  make install
)

test -s "$PREFIX/lib/libwolfssl.a"

BRIDGE_CFLAGS="-std=c11 -O2 -ffreestanding -fno-builtin -fshort-wchar -DWOLFSSL_USER_SETTINGS -I$PLATFORM_INCLUDE -I$SRC -I$PREFIX/include -isystem $MINGW_INCLUDE"

clang $BRIDGE_CFLAGS --target="$COFF_TARGET" \
  -c "$ROOT/vendor/wolfssl-bridge/uefi_tls.c" \
  -o "$BRIDGE_BUILD/uefi_tls.obj"
clang $BRIDGE_CFLAGS --target="$COFF_TARGET" \
  -c "$ROOT/vendor/wolfssl-bridge/uefi_platform.c" \
  -o "$BRIDGE_BUILD/uefi_platform.obj"
clang $BRIDGE_CFLAGS --target="$COFF_TARGET" \
  -c "$ROOT/vendor/wolfssl-bridge/uefi_crt.c" \
  -o "$BRIDGE_BUILD/uefi_crt.obj"

llvm-ar rcs "$BRIDGE_BUILD/libuefi_wolfssl_bridge.a" \
  "$BRIDGE_BUILD/uefi_tls.obj" \
  "$BRIDGE_BUILD/uefi_platform.obj" \
  "$BRIDGE_BUILD/uefi_crt.obj"

export UEFI_WOLFSSL_LIB_DIR="$PREFIX/lib"
export UEFI_WOLFSSL_BRIDGE_DIR="$BRIDGE_BUILD"

bash "$ROOT/scripts/update-ca-bundle.sh"

if [[ -f "$ROOT/assets/cacert.pem" ]]; then
  source "$ROOT/scripts/check-ca-bundle.sh"
  export UEFI_CA_BUNDLE_PATH="$ROOT/assets/cacert.pem"
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
