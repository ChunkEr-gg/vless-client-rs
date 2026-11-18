#!/bin/bash -p
#
# install-helper.sh — Idempotent root installer for vless-tray-helper (development / unsigned mode).
#
# Installs the launchd socket-activated daemon and records the authorized desktop
# user's numeric UID in /Library/Application Support/vless-tray/owner-uid so
# vless-tray-helper can authenticate every Unix socket peer via getpeereid(2).
#
# Usage:
#   sudo ./dist/install-helper.sh [--uid <uid>] [--helper <path>] [--plist <path>] [--allow-root-uid]
#
# Also invoked by `vless-tray install-helper` via:
#   osascript -e 'do shell script ".../install-helper.sh --uid <uid> --helper ... --plist ..." with administrator privileges'

set -euo pipefail
IFS=$' \t\n'
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
umask 077

readonly SERVICE_LABEL="io.vless-tray.helper"
readonly SERVICE_TARGET="system/${SERVICE_LABEL}"
readonly SUPPORT_DIR="/Library/Application Support/vless-tray"
readonly OWNER_UID_FILE="${SUPPORT_DIR}/owner-uid"
readonly HELPER_DIR="/Library/PrivilegedHelperTools"
readonly HELPER_DST="${HELPER_DIR}/vless-tray-helper"
readonly LAUNCHDAEMONS_DIR="/Library/LaunchDaemons"
readonly PLIST_DST="${LAUNCHDAEMONS_DIR}/${SERVICE_LABEL}.plist"
readonly SOCK_PATH="/var/run/vless-tray.sock"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<'EOF'
Usage: install-helper.sh [OPTIONS]

Install and bootstrap the io.vless-tray.helper LaunchDaemon as root.

Options:
  --uid <uid>        Numeric UID authorized to connect to /var/run/vless-tray.sock.
                     Defaults to $SUDO_UID when omitted. Must be > 0 unless
                     --allow-root-uid is also passed.
  --helper <path>    Path to the compiled vless-tray-helper binary.
  --plist <path>     Path to the io.vless-tray.helper.plist LaunchDaemon manifest.
  --allow-root-uid   Explicitly permit authorizing UID 0 (root) as owner-uid.
  -h, --help         Show this help text and exit.
EOF
}

die() {
    printf 'install-helper.sh: error: %s\n' "$*" >&2
    exit 1
}

validate_uid() {
    local uid_val="$1"
    local allow_root="$2"

    if [ -z "${uid_val}" ]; then
        die "authorized UID is empty; pass --uid <uid> or run via sudo from a non-root user"
    fi

    case "${uid_val}" in
        *[!0-9]*)
            die "invalid --uid '${uid_val}': must be a base-10 non-negative integer"
            ;;
    esac

    if [ "${#uid_val}" -gt 1 ]; then
        case "${uid_val}" in
            0*)
                die "invalid --uid '${uid_val}': leading zeros are not permitted"
                ;;
        esac
    fi

    if [ "${uid_val}" -eq 0 ] && [ "${allow_root}" -ne 1 ]; then
        die "refusing to authorize UID 0 (root) without --allow-root-uid; pass a normal user's --uid <uid>"
    fi

    # Reject (uid_t)-2 (4294967294, nobody) and >= (uid_t)-1 (4294967295).
    if [ "${uid_val}" -gt 4294967293 ]; then
        die "invalid --uid '${uid_val}': out of valid macOS user UID range"
    fi
}

OWNER_UID=""
UID_EXPLICIT=0
ALLOW_ROOT_UID=0
HELPER_SRC=""
PLIST_SRC=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --uid)
            [ "$#" -ge 2 ] || die "--uid requires a numeric argument"
            OWNER_UID="$2"
            UID_EXPLICIT=1
            shift 2
            ;;
        --uid=*)
            OWNER_UID="${1#--uid=}"
            UID_EXPLICIT=1
            shift
            ;;
        --helper)
            [ "$#" -ge 2 ] || die "--helper requires a file path argument"
            HELPER_SRC="$2"
            shift 2
            ;;
        --helper=*)
            HELPER_SRC="${1#--helper=}"
            shift
            ;;
        --plist)
            [ "$#" -ge 2 ] || die "--plist requires a file path argument"
            PLIST_SRC="$2"
            shift 2
            ;;
        --plist=*)
            PLIST_SRC="${1#--plist=}"
            shift
            ;;
        --allow-root-uid|--allow-root)
            ALLOW_ROOT_UID=1
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

if [ "${UID_EXPLICIT}" -eq 1 ]; then
    validate_uid "${OWNER_UID}" "${ALLOW_ROOT_UID}"
fi

if [ "$(id -u)" -ne 0 ]; then
    die "must be run as root (use 'sudo ./dist/install-helper.sh' or 'vless-tray install-helper')"
fi

if [ "${UID_EXPLICIT}" -eq 0 ]; then
    OWNER_UID="${SUDO_UID:-}"
    if [ -z "${OWNER_UID}" ]; then
        die "--uid <uid> is required when SUDO_UID is not set"
    fi
    validate_uid "${OWNER_UID}" "${ALLOW_ROOT_UID}"
fi

if [ "$(uname -s)" != "Darwin" ]; then
    die "io.vless-tray.helper can only be installed on macOS (Darwin)"
fi

# Resolve default --helper path if omitted (supports both .app bundle and workspace layouts).
if [ -z "${HELPER_SRC}" ]; then
    if [ -f "${SCRIPT_DIR}/../Library/LaunchDaemons/vless-tray-helper" ]; then
        HELPER_SRC="${SCRIPT_DIR}/../Library/LaunchDaemons/vless-tray-helper"
    elif [ -f "${SCRIPT_DIR}/../target/release/vless-tray-helper" ]; then
        HELPER_SRC="${SCRIPT_DIR}/../target/release/vless-tray-helper"
    elif [ -f "${SCRIPT_DIR}/../target/debug/vless-tray-helper" ]; then
        HELPER_SRC="${SCRIPT_DIR}/../target/debug/vless-tray-helper"
    else
        die "could not locate vless-tray-helper binary; build it first or pass --helper <path>"
    fi
fi

# Resolve default --plist path if omitted (supports both .app bundle and workspace layouts).
if [ -z "${PLIST_SRC}" ]; then
    if [ -f "${SCRIPT_DIR}/io.vless-tray.helper.dev.plist" ]; then
        PLIST_SRC="${SCRIPT_DIR}/io.vless-tray.helper.dev.plist"
    elif [ -f "${SCRIPT_DIR}/io.vless-tray.helper.plist" ]; then
        PLIST_SRC="${SCRIPT_DIR}/io.vless-tray.helper.plist"
    else
        die "could not locate io.vless-tray.helper.plist; pass --plist <path>"
    fi
fi

[ -f "${HELPER_SRC}" ] || die "helper binary does not exist or is not a regular file: ${HELPER_SRC}"
[ -s "${HELPER_SRC}" ] || die "helper binary is empty: ${HELPER_SRC}"
[ -f "${PLIST_SRC}" ] || die "launchd plist does not exist or is not a regular file: ${PLIST_SRC}"
[ -s "${PLIST_SRC}" ] || die "launchd plist is empty: ${PLIST_SRC}"

if [ -x /usr/bin/plutil ]; then
    /usr/bin/plutil -lint -s "${PLIST_SRC}" || die "invalid property list syntax: ${PLIST_SRC}"
fi

# Refuse symlinked target directories.
[ ! -L "${SUPPORT_DIR}" ] || die "refusing to use symlinked directory: ${SUPPORT_DIR}"
[ ! -L "${HELPER_DIR}" ] || die "refusing to use symlinked directory: ${HELPER_DIR}"
[ ! -L "${LAUNCHDAEMONS_DIR}" ] || die "refusing to use symlinked directory: ${LAUNCHDAEMONS_DIR}"

OWNER_UID_TMP=""
HELPER_TMP=""
PLIST_TMP=""

cleanup_staging() {
    if [ -n "${OWNER_UID_TMP}" ]; then
        rm -f "${OWNER_UID_TMP}"
    fi
    if [ -n "${HELPER_TMP}" ]; then
        rm -f "${HELPER_TMP}"
    fi
    if [ -n "${PLIST_TMP}" ]; then
        rm -f "${PLIST_TMP}"
    fi
}
trap cleanup_staging EXIT

# 1. Unload any prior helper instance cleanly and wait for launchd teardown to finish
#    before replacing binaries/plist or running bootstrap.
/bin/launchctl bootout "${SERVICE_TARGET}" 2>/dev/null || true
bootout_attempt=0
while [ "${bootout_attempt}" -lt 20 ] && /bin/launchctl print "${SERVICE_TARGET}" >/dev/null 2>&1; do
    sleep 0.1
    bootout_attempt=$((bootout_attempt + 1))
done
rm -f "${SOCK_PATH}"

# 2. Create /Library/Application Support/vless-tray (root:wheel, 0700) and
#    atomically write the authorized caller UID to owner-uid (root:wheel, 0600).
install -d -o root -g wheel -m 0700 "${SUPPORT_DIR}"
chown root:wheel "${SUPPORT_DIR}"
chmod 0700 "${SUPPORT_DIR}"

OWNER_UID_TMP="${SUPPORT_DIR}/.owner-uid.tmp.$$"
rm -f "${OWNER_UID_TMP}"
printf '%s\n' "${OWNER_UID}" > "${OWNER_UID_TMP}"
chown root:wheel "${OWNER_UID_TMP}"
chmod 0600 "${OWNER_UID_TMP}"
/bin/sync
mv -f "${OWNER_UID_TMP}" "${OWNER_UID_FILE}"
OWNER_UID_TMP=""

# 3. Stage and atomically rename vless-tray-helper into /Library/PrivilegedHelperTools
#    (root:wheel, 0755). Staging to a fresh inode avoids macOS Apple Silicon vnode
#    code-signature cache invalidation (SIGKILL on in-place Mach-O overwrite).
install -d -o root -g wheel -m 0755 "${HELPER_DIR}"
HELPER_TMP="${HELPER_DIR}/.vless-tray-helper.tmp.$$"
rm -f "${HELPER_TMP}"
install -o root -g wheel -m 0755 "${HELPER_SRC}" "${HELPER_TMP}"
mv -f "${HELPER_TMP}" "${HELPER_DST}"
HELPER_TMP=""

/usr/bin/xattr -c "${HELPER_DST}" 2>/dev/null || true
if [ -x /usr/bin/codesign ] && ! /usr/bin/codesign -v "${HELPER_DST}" >/dev/null 2>&1; then
    /usr/bin/codesign -f -s - "${HELPER_DST}"
fi

# 4. Stage and atomically rename io.vless-tray.helper.plist into /Library/LaunchDaemons
#    (root:wheel, 0644).
install -d -o root -g wheel -m 0755 "${LAUNCHDAEMONS_DIR}"
PLIST_TMP="${LAUNCHDAEMONS_DIR}/.${SERVICE_LABEL}.plist.tmp.$$"
rm -f "${PLIST_TMP}"
install -o root -g wheel -m 0644 "${PLIST_SRC}" "${PLIST_TMP}"
mv -f "${PLIST_TMP}" "${PLIST_DST}"
PLIST_TMP=""

/usr/bin/xattr -c "${PLIST_DST}" 2>/dev/null || true

# 5. Clear any disabled override and bootstrap into launchd's system domain.
/bin/launchctl enable "${SERVICE_TARGET}" 2>/dev/null || true
/bin/launchctl bootstrap system "${PLIST_DST}"

printf 'Installed %s (authorized owner UID: %s)\n' "${SERVICE_LABEL}" "${OWNER_UID}"
