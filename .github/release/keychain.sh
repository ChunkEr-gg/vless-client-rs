#!/usr/bin/env bash
set -euo pipefail
: "${P12_B64:?}" "${P12_PASSWORD:?}"
umask 077
keychain="$RUNNER_TEMP/release.keychain-db"
certificate="$RUNNER_TEMP/signing.p12"
trap 'rm -f "$certificate"' EXIT
password=$(openssl rand -hex 32)
printf '%s' "$P12_B64" | base64 -D > "$certificate"
security create-keychain -p "$password" "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$password" "$keychain"
security import "$certificate" -k "$keychain" -P "$P12_PASSWORD" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple: -s -k "$password" "$keychain" >/dev/null
security list-keychains -d user -s "$keychain" "$HOME/Library/Keychains/login.keychain-db"
