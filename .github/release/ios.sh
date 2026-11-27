#!/usr/bin/env bash
set -euo pipefail
: "${TEAM_ID:?}" "${BUNDLE_ID:?}" "${APP_PROFILE_B64:?}" "${TUNNEL_PROFILE_B64:?}"
profiles="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"
mkdir -p "$profiles" signed
# Extract names from the supplied profiles so the app and its extension are signed independently.
install_profile() (
    umask 077
    local tmp="$RUNNER_TEMP/$2" plist="$RUNNER_TEMP/$2.plist" uuid
    printf '%s' "$1" | base64 -D > "$tmp"
    security cms -D -i "$tmp" > "$plist"
    uuid=$(plutil -extract UUID raw "$plist")
    cp "$tmp" "$profiles/$uuid.mobileprovision"
    plutil -extract Name raw "$plist"
)
app_profile=$(install_profile "$APP_PROFILE_B64" app)
tunnel_profile=$(install_profile "$TUNNEL_PROFILE_B64" tunnel)
command -v xcodegen || brew install xcodegen
xcodegen generate --spec ios/project.yml
archive="$RUNNER_TEMP/client.xcarchive"
xcodebuild -project ios/VlessClient.xcodeproj -scheme VlessClient -configuration Release \
    -destination 'generic/platform=iOS' -archivePath "$archive" DEVELOPMENT_TEAM="$TEAM_ID" \
    CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY="Apple Distribution" VLESS_BUNDLE_IDENTIFIER="$BUNDLE_ID" \
    APP_PROFILE_NAME="$app_profile" TUNNEL_PROFILE_NAME="$tunnel_profile" \
    MARKETING_VERSION="$RELEASE_VERSION" CURRENT_PROJECT_VERSION="$RELEASE_VERSION" archive
python3 - "$TEAM_ID" "$BUNDLE_ID" "$app_profile" "$tunnel_profile" <<'PY'
import os, plistlib, sys
team, app, profile, tunnel = sys.argv[1:]
with open(os.path.join(os.environ["RUNNER_TEMP"], "export.plist"), "wb") as out:
    plistlib.dump(dict(method="app-store-connect", destination="export", teamID=team, signingStyle="manual",
                       manageAppVersionAndBuildNumber=False, signingCertificate="Apple Distribution",
                       provisioningProfiles={app: profile, app + ".tunnel": tunnel}), out)
PY
xcodebuild -exportArchive -archivePath "$archive" -exportPath "$RUNNER_TEMP/export" \
    -exportOptionsPlist "$RUNNER_TEMP/export.plist"
cp "$RUNNER_TEMP/export/"*.ipa "signed/VlessClient-$RELEASE_VERSION.ipa"
unzip -q "signed/VlessClient-$RELEASE_VERSION.ipa" -d "$RUNNER_TEMP/ipa"
codesign --verify --deep --strict "$RUNNER_TEMP/ipa/Payload/VlessClient.app"
