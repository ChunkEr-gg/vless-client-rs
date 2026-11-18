#!/bin/bash -p
#
# uninstall-helper.sh — Cleanly stop, recover network state, and remove vless-tray-helper.
#
# Usage:
#   sudo ./dist/uninstall-helper.sh [--helper <path>]

set -euo pipefail
IFS=$' \t\n'
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
umask 077

readonly SERVICE_LABEL="io.vless-tray.helper"
readonly SERVICE_TARGET="system/${SERVICE_LABEL}"
readonly SUPPORT_DIR="/Library/Application Support/vless-tray"
readonly STATE_FILE="${SUPPORT_DIR}/helper-state.json"
readonly HELPER_DST="/Library/PrivilegedHelperTools/vless-tray-helper"
readonly PLIST_DST="/Library/LaunchDaemons/${SERVICE_LABEL}.plist"
readonly SOCK_PATH="/var/run/vless-tray.sock"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<'EOF'
Usage: uninstall-helper.sh [OPTIONS]

Stop and remove io.vless-tray.helper, restoring any saved network/DNS/proxy state first.

Options:
  --helper <path>    Optional fallback vless-tray-helper binary to run --recover-only
                     if /Library/PrivilegedHelperTools/vless-tray-helper is already absent.
  -h, --help         Show this help text and exit.
EOF
}

die() {
    printf 'uninstall-helper.sh: error: %s\n' "$*" >&2
    exit 1
}

warn() {
    printf 'uninstall-helper.sh: warning: %s\n' "$*" >&2
}

FALLBACK_HELPER=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --helper)
            [ "$#" -ge 2 ] || die "--helper requires a file path argument"
            FALLBACK_HELPER="$2"
            shift 2
            ;;
        --helper=*)
            FALLBACK_HELPER="${1#--helper=}"
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

if [ "$(id -u)" -ne 0 ]; then
    die "must be run as root (use 'sudo ./dist/uninstall-helper.sh')"
fi

if [ "$(uname -s)" != "Darwin" ]; then
    die "io.vless-tray.helper can only be uninstalled on macOS (Darwin)"
fi

# 1. Stop and unload the LaunchDaemon from launchd's system domain, waiting until
#    launchd confirms unload so --recover-only never races with a live daemon.
/bin/launchctl bootout "${SERVICE_TARGET}" 2>/dev/null || true
bootout_attempt=0
while [ "${bootout_attempt}" -lt 20 ] && /bin/launchctl print "${SERVICE_TARGET}" >/dev/null 2>&1; do
    sleep 0.1
    bootout_attempt=$((bootout_attempt + 1))
done

# 2. If a state journal still exists on disk, invoke --recover-only before deleting
#    the helper binary or state directory so no routes, DNS entries, or system proxy
#    overrides remain behind after uninstall.
if [ -f "${STATE_FILE}" ]; then
    RECOVERY_BIN=""
    if [ -x "${HELPER_DST}" ] && [ ! -L "${HELPER_DST}" ]; then
        RECOVERY_BIN="${HELPER_DST}"
    elif [ -n "${FALLBACK_HELPER}" ] && [ -x "${FALLBACK_HELPER}" ] && [ ! -L "${FALLBACK_HELPER}" ]; then
        RECOVERY_BIN="${FALLBACK_HELPER}"
    elif [ -x "${SCRIPT_DIR}/../Library/LaunchDaemons/vless-tray-helper" ] && [ ! -L "${SCRIPT_DIR}/../Library/LaunchDaemons/vless-tray-helper" ]; then
        RECOVERY_BIN="${SCRIPT_DIR}/../Library/LaunchDaemons/vless-tray-helper"
    fi

    if [ -n "${RECOVERY_BIN}" ]; then
        if ! "${RECOVERY_BIN}" --recover-only; then
            warn "'${RECOVERY_BIN} --recover-only' exited non-zero; proceeding with file removal"
        fi
    else
        warn "found ${STATE_FILE} but no executable vless-tray-helper binary to run --recover-only"
    fi
fi

# 3. Remove LaunchDaemon plist, privileged helper binary, Unix domain socket,
#    and /Library/Application Support/vless-tray.
rm -f "${PLIST_DST}"
rm -f "${HELPER_DST}"
rm -f "${SOCK_PATH}"

if [ "${SUPPORT_DIR}" = "/Library/Application Support/vless-tray" ]; then
    if [ -L "${SUPPORT_DIR}" ]; then
        rm -f "${SUPPORT_DIR}"
    elif [ -d "${SUPPORT_DIR}" ]; then
        rm -rf "${SUPPORT_DIR}"
    fi
fi

printf 'Uninstalled %s and cleaned up privileged helper state.\n' "${SERVICE_LABEL}"
