#!/usr/bin/env bash
set -euo pipefail
: "${MACOS_IDENTITY:?}" "${NOTARY_KEY_B64:?}" "${NOTARY_KEY_ID:?}" "${NOTARY_ISSUER:?}"
[[ "$MACOS_IDENTITY" == "Developer ID Application: "* ]]
mkdir -p signed
key="$RUNNER_TEMP/notary.p8"
trap 'rm -f "$key"' EXIT
(umask 077; printf '%s' "$NOTARY_KEY_B64" | base64 -D > "$key")
for product in Tray Profiles; do
    dir="$RUNNER_TEMP/$product"
    mkdir -p "$dir"
    ditto -x -k "validation/$product/"*.zip "$dir"
    app="$dir/VLESS $product.app"
    plist="$app/Contents/Info.plist"
    plutil -replace CFBundleVersion -string "$RELEASE_VERSION" "$plist"
    plutil -replace CFBundleShortVersionString -string "$RELEASE_VERSION" "$plist"
    args=(--force --options runtime --timestamp --sign "$MACOS_IDENTITY")
    if [[ "$product" == Tray ]]; then
        codesign "${args[@]}" "$app/Contents/Library/LaunchDaemons/vless-tray-helper"
        codesign "${args[@]}" "$app/Contents/MacOS/vless-engine"
    else
        codesign "${args[@]}" "$app/Contents/MacOS/reality-sing-box"
    fi
    codesign "${args[@]}" "$app"
    codesign --verify --deep --strict "$app"
    ditto -c -k --keepParent "$app" "$dir/submit.zip"
    xcrun notarytool submit "$dir/submit.zip" --key "$key" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER" --wait
    xcrun stapler staple "$app"
    xcrun stapler validate "$app"
    ditto -c -k --keepParent "$app" "signed/VLESS-$product-$RELEASE_VERSION.zip"
done
