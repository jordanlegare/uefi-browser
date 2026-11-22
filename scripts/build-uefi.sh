#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="x86_64-unknown-uefi"
VERSION="4.3.0"
SRC="$ROOT/vendor/mbedtls-$VERSION"
BUILD="$ROOT/build/mbedtls-$VERSION"
PREFIX="$ROOT/build/mbedtls-install"

"$ROOT/scripts/fetch-mbedtls.sh"

command -v cmake >/dev/null
command -v ninja >/dev/null
command -v clang >/dev/null
rustup target add "$TARGET"

cmake -S "$SRC" -B "$BUILD" -G Ninja \
  -DCMAKE_SYSTEM_NAME=Generic \
  -DCMAKE_SYSTEM_PROCESSOR=x86_64 \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_C_COMPILER_TARGET=x86_64-pc-win32-coff \
  -DCMAKE_C_FLAGS="-ffreestanding -fno-builtin -fshort-wchar" \
  -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DUSE_SHARED_MBEDTLS_LIBRARY=OFF \
  -DUSE_STATIC_MBEDTLS_LIBRARY=ON \
  -DENABLE_PROGRAMS=OFF \
  -DENABLE_TESTING=OFF

cmake --build "$BUILD" --parallel
cmake --install "$BUILD"

echo "Mbed TLS source has been staged."
echo "The complete UEFI link still needs the C-runtime, clock/RNG and TCP4/DNS4 adapters."
