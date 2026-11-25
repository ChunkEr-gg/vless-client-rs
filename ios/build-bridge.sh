#!/usr/bin/env bash
set -euo pipefail
cd "$SRCROOT/.."
export PATH="$HOME/.cargo/bin:$PATH"
case "$PLATFORM_NAME/$CURRENT_ARCH" in
    iphoneos/*) target=aarch64-apple-ios ;;
    iphonesimulator/x86_64) target=x86_64-apple-ios ;;
    iphonesimulator/*) target=aarch64-apple-ios-sim ;;
    *) echo "Unsupported platform: $PLATFORM_NAME" >&2; exit 1 ;;
esac
export CARGO_TARGET_DIR="$PROJECT_TEMP_DIR/rust"
rustup target add "$target"
cargo build --locked --release --target "$target" -p vless-mobile
mkdir -p "$BUILT_PRODUCTS_DIR"
cp "$CARGO_TARGET_DIR/$target/release/libvless_mobile.a" "$BUILT_PRODUCTS_DIR/"
