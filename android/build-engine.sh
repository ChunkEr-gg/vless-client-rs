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
case ${1:-arm64-v8a} in
    arm64-v8a) target=aarch64-linux-android; libs=android/app/src/main/jniLibs/arm64-v8a ;;
    x86_64) target=x86_64-linux-android; libs=android/app/src/debug/jniLibs/x86_64 ;;
    *) echo "Unsupported Android ABI: $1" >&2; exit 1 ;;
esac
target_env=${target//-/_}
export "CC_$target_env=$bin/${target}24-clang"
export "CXX_$target_env=$bin/${target}24-clang++"
export "AR_$target_env=$bin/llvm-ar"
# Bash 3 on macOS lacks uppercase parameter expansion.
linker_env=$(echo "$target_env" | tr '[:lower:]' '[:upper:]')
export "CARGO_TARGET_${linker_env}_LINKER=$bin/${target}24-clang"
cargo rustc --locked --release --target "$target" -p vless-engine --bin vless-engine -- -C link-arg=-Wl,-z,max-page-size=16384
mkdir -p "$libs"
install -m 755 "${CARGO_TARGET_DIR:-target}/$target/release/vless-engine" "$libs/libvless_engine.so"
