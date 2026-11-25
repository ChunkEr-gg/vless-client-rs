#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to an installed Android NDK}"
case "$(uname -s)" in
    Linux) host=linux-x86_64 ;;
    Darwin) host=darwin-x86_64 ;;
    *) echo "Run this build on Linux or macOS" >&2; exit 1 ;;
esac
bin="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$host/bin"
export CC_aarch64_linux_android="$bin/aarch64-linux-android24-clang"
export CXX_aarch64_linux_android="$bin/aarch64-linux-android24-clang++"
export AR_aarch64_linux_android="$bin/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC_aarch64_linux_android"
cargo rustc --locked --release --target aarch64-linux-android -p vless-engine --bin vless-engine -- -C link-arg=-Wl,-z,max-page-size=16384
libs=android/app/src/main/jniLibs/arm64-v8a
mkdir -p "$libs"
install -m 755 "${CARGO_TARGET_DIR:-target}/aarch64-linux-android/release/vless-engine" "$libs/libvless_engine.so"
