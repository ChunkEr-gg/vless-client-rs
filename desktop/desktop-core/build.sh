#!/bin/sh
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
out=${1:-"$here/../../target/release/reality-sing-box"}
case "$out" in /*) ;; *) out="$PWD/$out" ;; esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -fsSL https://codeload.github.com/SagerNet/sing-box/tar.gz/refs/tags/v1.14.4 -o "$work/source.tgz"
(cd "$work" && if command -v sha256sum >/dev/null; then sum='sha256sum'; else sum='shasum -a 256'; fi && echo '0958ccd23b1ea9a141d715d15478b1e040fd04bcca19d8ff5529636b1b753e18  source.tgz' | $sum -c -)
tar xf "$work/source.tgz" -C "$work" --strip-components=1
cd "$work"
patch -p1 < "$here/desktop.patch"
mkdir -p "$(dirname "$out")"
go build -trimpath -tags with_utls -o "$out" ./cmd/sing-box
