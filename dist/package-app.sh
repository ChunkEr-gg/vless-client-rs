#!/bin/bash
#
# package-app.sh — Assemble "VLESS Tray.app" in target/dist/ from built release binaries.
#
# Bundle layout produced:
#   VLESS Tray.app/
#   └─ Contents/
#      ├─ Info.plist
#      ├─ MacOS/
#      │  ├─ vless-tray
#      │  └─ vless-engine
#      ├─ Library/
#      │  └─ LaunchDaemons/
#      │     ├─ vless-tray-helper
#      │     └─ io.vless-tray.helper.plist     (SMAppService BundleProgram manifest)
#      └─ Resources/
#         ├─ install-helper.sh
#         ├─ uninstall-helper.sh
#         └─ io.vless-tray.helper.dev.plist    (Development /Library/LaunchDaemons manifest)

set -euo pipefail
IFS=$' \t\n'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

readonly APP_NAME="VLESS Tray.app"
readonly INFO_PLIST_SRC="${SCRIPT_DIR}/Info.plist"
readonly SMAPPSERVICE_PLIST_SRC="${SCRIPT_DIR}/io.vless-tray.helper.smappservice.plist"
readonly DEV_PLIST_SRC="${SCRIPT_DIR}/io.vless-tray.helper.plist"
readonly INSTALL_SCRIPT_SRC="${SCRIPT_DIR}/install-helper.sh"
readonly UNINSTALL_SCRIPT_SRC="${SCRIPT_DIR}/uninstall-helper.sh"

usage() {
    cat <<'EOF'
Usage: package-app.sh [OPTIONS]

Assemble "VLESS Tray.app" from built workspace binaries (vless-tray, vless-engine,
vless-tray-helper) and the manifests/scripts in dist/.

Options:
  --build               Run `cargo build --release --bins` before packaging.
  --target <triple>     Rust target triple subdirectory (e.g. aarch64-apple-darwin).
  --profile <profile>   Cargo build profile directory name (default: release).
  --bin-dir <dir>       Explicit directory containing vless-tray, vless-engine, and
                        vless-tray-helper (overrides --target / --profile lookup).
  --out-dir <dir>       Output directory for "VLESS Tray.app" (default: target/dist).
  --codesign <identity> macOS codesign identity (defaults to "-" ad-hoc on Darwin;
                        pass "" or CODESIGN_IDENTITY="" to skip signing, or
                        "Developer ID Application: ..." for distribution). Signs inside-out.
  -h, --help            Show this help text and exit.
EOF
}

die() {
    printf 'package-app.sh: error: %s\n' "$*" >&2
    exit 1
}

DO_BUILD=0
TARGET_TRIPLE=""
PROFILE="release"
BIN_DIR=""
OUT_DIR=""
if [ "${CODESIGN_IDENTITY+x}" = "x" ]; then
    CODESIGN_EXPLICIT=1
else
    CODESIGN_EXPLICIT=0
    CODESIGN_IDENTITY=""
fi

while [ "$#" -gt 0 ]; do
    case "$1" in
        --build)
            DO_BUILD=1
            shift
            ;;
        --target)
            [ "$#" -ge 2 ] || die "--target requires a Rust target triple"
            TARGET_TRIPLE="$2"
            shift 2
            ;;
        --target=*)
            TARGET_TRIPLE="${1#--target=}"
            shift
            ;;
        --profile)
            [ "$#" -ge 2 ] || die "--profile requires a profile name"
            PROFILE="$2"
            shift 2
            ;;
        --profile=*)
            PROFILE="${1#--profile=}"
            shift
            ;;
        --bin-dir)
            [ "$#" -ge 2 ] || die "--bin-dir requires a directory path"
            BIN_DIR="$2"
            shift 2
            ;;
        --bin-dir=*)
            BIN_DIR="${1#--bin-dir=}"
            shift
            ;;
        --out-dir)
            [ "$#" -ge 2 ] || die "--out-dir requires a directory path"
            OUT_DIR="$2"
            shift 2
            ;;
        --out-dir=*)
            OUT_DIR="${1#--out-dir=}"
            shift
            ;;
        --codesign)
            [ "$#" -ge 2 ] || die "--codesign requires a signing identity (or \"\" to skip signing)"
            CODESIGN_IDENTITY="$2"
            CODESIGN_EXPLICIT=1
            shift 2
            ;;
        --codesign=*)
            CODESIGN_IDENTITY="${1#--codesign=}"
            CODESIGN_EXPLICIT=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: '$1' (pass --help for usage)"
            ;;
    esac
done

TARGET_ROOT="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}"

if [ -z "${OUT_DIR}" ]; then
    OUT_DIR="${REPO_ROOT}/target/dist"
fi

if [ "${DO_BUILD}" -eq 1 ]; then
    BUILD_ARGS=(build --locked -p vless-tray -p vless-engine -p vless-tray-helper --bins)
    if [ "${PROFILE}" = "release" ]; then
        BUILD_ARGS+=(--release)
    elif [ "${PROFILE}" != "debug" ]; then
        BUILD_ARGS+=(--profile "${PROFILE}")
    fi
    if [ -n "${TARGET_TRIPLE}" ]; then
        BUILD_ARGS+=(--target "${TARGET_TRIPLE}")
    fi
    (
        cd "${REPO_ROOT}"
        cargo "${BUILD_ARGS[@]}"
    )
fi

if [ -z "${BIN_DIR}" ]; then
    if [ -n "${TARGET_TRIPLE}" ]; then
        BIN_DIR="${TARGET_ROOT}/${TARGET_TRIPLE}/${PROFILE}"
    else
        BIN_DIR="${TARGET_ROOT}/${PROFILE}"
    fi
fi

# Verify dist/ source assets exist.
for asset in \
    "${INFO_PLIST_SRC}" \
    "${SMAPPSERVICE_PLIST_SRC}" \
    "${DEV_PLIST_SRC}" \
    "${INSTALL_SCRIPT_SRC}" \
    "${UNINSTALL_SCRIPT_SRC}"; do
    [ -f "${asset}" ] || die "missing required dist asset: ${asset}"
    [ -s "${asset}" ] || die "dist asset is empty: ${asset}"
done

# Verify built binaries exist.
TRAY_BIN="${BIN_DIR}/vless-tray"
ENGINE_BIN="${BIN_DIR}/vless-engine"
HELPER_BIN="${BIN_DIR}/vless-tray-helper"

for bin_path in "${TRAY_BIN}" "${ENGINE_BIN}" "${HELPER_BIN}"; do
    if [ ! -f "${bin_path}" ]; then
        die "missing compiled binary: ${bin_path} (run 'cargo build --release' first or pass --build / --bin-dir)"
    fi
    if [ ! -s "${bin_path}" ]; then
        die "compiled binary is empty: ${bin_path}"
    fi
done

IS_DARWIN=0
if [ "$(uname -s)" = "Darwin" ]; then
    IS_DARWIN=1
fi

if [ "${IS_DARWIN}" -eq 1 ] && [ "${CODESIGN_EXPLICIT}" -eq 0 ]; then
    CODESIGN_IDENTITY="-"
fi

mkdir -p "${OUT_DIR}"
chmod 0755 "${OUT_DIR}"

STAGE_PARENT="${OUT_DIR}/.staging.$$"
STAGE_APP="${STAGE_PARENT}/${APP_NAME}"
FINAL_APP="${OUT_DIR}/${APP_NAME}"

cleanup_staging() {
    if [ -n "${STAGE_PARENT:-}" ] && [ -d "${STAGE_PARENT}" ]; then
        rm -rf "${STAGE_PARENT}"
    fi
}
trap cleanup_staging EXIT

rm -rf "${STAGE_PARENT}"

CONTENTS_DIR="${STAGE_APP}/Contents"
MACOS_DIR="${CONTENTS_DIR}/MacOS"
LAUNCHDAEMONS_DIR="${CONTENTS_DIR}/Library/LaunchDaemons"
RESOURCES_DIR="${CONTENTS_DIR}/Resources"

mkdir -p "${MACOS_DIR}" "${LAUNCHDAEMONS_DIR}" "${RESOURCES_DIR}"
chmod 0755 \
    "${STAGE_PARENT}" \
    "${STAGE_APP}" \
    "${CONTENTS_DIR}" \
    "${MACOS_DIR}" \
    "${CONTENTS_DIR}/Library" \
    "${LAUNCHDAEMONS_DIR}" \
    "${RESOURCES_DIR}"

# Bundle manifest
cp -f "${INFO_PLIST_SRC}" "${CONTENTS_DIR}/Info.plist"
chmod 0644 "${CONTENTS_DIR}/Info.plist"

# Main app + engine child executable
cp -f "${TRAY_BIN}" "${MACOS_DIR}/vless-tray"
chmod 0755 "${MACOS_DIR}/vless-tray"

cp -f "${ENGINE_BIN}" "${MACOS_DIR}/vless-engine"
chmod 0755 "${MACOS_DIR}/vless-engine"

# SMAppService daemon layout (Contents/Library/LaunchDaemons/)
cp -f "${HELPER_BIN}" "${LAUNCHDAEMONS_DIR}/vless-tray-helper"
chmod 0755 "${LAUNCHDAEMONS_DIR}/vless-tray-helper"

cp -f "${SMAPPSERVICE_PLIST_SRC}" "${LAUNCHDAEMONS_DIR}/io.vless-tray.helper.plist"
chmod 0644 "${LAUNCHDAEMONS_DIR}/io.vless-tray.helper.plist"

# Development helper installer/uninstaller & /Library/LaunchDaemons plist
cp -f "${INSTALL_SCRIPT_SRC}" "${RESOURCES_DIR}/install-helper.sh"
chmod 0755 "${RESOURCES_DIR}/install-helper.sh"

cp -f "${UNINSTALL_SCRIPT_SRC}" "${RESOURCES_DIR}/uninstall-helper.sh"
chmod 0755 "${RESOURCES_DIR}/uninstall-helper.sh"

cp -f "${DEV_PLIST_SRC}" "${RESOURCES_DIR}/io.vless-tray.helper.dev.plist"
chmod 0644 "${RESOURCES_DIR}/io.vless-tray.helper.dev.plist"

if [ -x /usr/bin/plutil ]; then
    /usr/bin/plutil -lint -s "${CONTENTS_DIR}/Info.plist"
    /usr/bin/plutil -lint -s "${LAUNCHDAEMONS_DIR}/io.vless-tray.helper.plist"
    /usr/bin/plutil -lint -s "${RESOURCES_DIR}/io.vless-tray.helper.dev.plist"
fi

if [ "${IS_DARWIN}" -eq 1 ] && [ -x /usr/bin/xattr ]; then
    /usr/bin/xattr -cr "${STAGE_APP}" 2>/dev/null || true
fi

if [ -n "${CODESIGN_IDENTITY}" ]; then
    if ! command -v codesign >/dev/null 2>&1; then
        die "--codesign requested, but 'codesign' is not available on this host"
    fi
    CODESIGN_FLAGS=(--force --sign "${CODESIGN_IDENTITY}")
    if [ "${CODESIGN_IDENTITY}" != "-" ]; then
        CODESIGN_FLAGS+=(--options runtime --timestamp)
    fi
    # Sign nested executables inside-out while leaf directory name is literally "VLESS Tray.app".
    codesign "${CODESIGN_FLAGS[@]}" "${LAUNCHDAEMONS_DIR}/vless-tray-helper"
    codesign "${CODESIGN_FLAGS[@]}" "${MACOS_DIR}/vless-engine"
    codesign "${CODESIGN_FLAGS[@]}" "${STAGE_APP}"
fi

if [ -e "${FINAL_APP}" ] || [ -L "${FINAL_APP}" ]; then
    mv "${FINAL_APP}" "${STAGE_PARENT}/old-app"
fi
mv "${STAGE_APP}" "${FINAL_APP}"
rm -rf "${STAGE_PARENT}"
STAGE_PARENT=""

printf 'Packaged app bundle: %s\n' "${FINAL_APP}"
