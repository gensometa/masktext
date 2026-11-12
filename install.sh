#!/bin/sh
# Usage: sh install.sh OWNER/REPO [v0.1.0]
set -eu

die() { printf '%s\n' "masktext installer: $*" >&2; exit 1; }
repo=${1:-}
version=${2:-latest}
case "$repo" in
  ''|*[!A-Za-z0-9_./-]*|/*|*..*) die 'provide a GitHub repository as OWNER/REPO' ;;
esac
owner=${repo%%/*}
project=${repo#*/}
[ "$owner" != "$project" ] && [ -n "$project" ] || die 'provide OWNER/REPO'
case "$project" in */*) die 'provide OWNER/REPO' ;; esac
case "$version" in latest|v[0-9]*) ;; *) die 'version must be latest or vVERSION' ;; esac
case "$version" in *[!A-Za-z0-9._-]*|*..*) die 'invalid version' ;; esac

for tool in curl tar mktemp; do command -v "$tool" >/dev/null 2>&1 || die "required command missing: $tool"; done
case "$(uname -s)" in Darwin) platform=darwin ;; Linux) platform=linux ;; *) die 'supported platforms: Linux and macOS' ;; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; *) die 'supported architectures: amd64 and arm64' ;; esac
if command -v sha256sum >/dev/null 2>&1; then hash_tool=sha256sum
elif command -v shasum >/dev/null 2>&1; then hash_tool=shasum
else die 'sha256sum or shasum is required'; fi

asset="masktext_${platform}_${arch}.tar.gz"
base="https://github.com/$repo/releases"
if [ "$version" = latest ]; then base="$base/latest/download"; else base="$base/download/$version"; fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
curl -fsSL --proto '=https' --tlsv1.2 "$base/$asset" -o "$work/$asset"
curl -fsSL --proto '=https' --tlsv1.2 "$base/SHA256SUMS" -o "$work/SHA256SUMS"
expected=$(awk -v asset="$asset" '$2 == asset {print $1}' "$work/SHA256SUMS")
[ ${#expected} -eq 64 ] || die 'missing or invalid checksum'
case "$expected" in *[!a-fA-F0-9]*) die 'invalid checksum' ;; esac
if [ "$hash_tool" = sha256sum ]; then actual=$(sha256sum "$work/$asset"); else actual=$(shasum -a 256 "$work/$asset"); fi
actual=${actual%% *}
[ "$expected" = "$actual" ] || die 'checksum mismatch'
tar -xzf "$work/$asset" -C "$work" masktext
[ -f "$work/masktext" ] && [ ! -L "$work/masktext" ] || die 'invalid binary in archive'
dest=${MASKTEXT_INSTALL_DIR:-"$HOME/.local/bin"}
mkdir -p "$dest"
[ ! -d "$dest/masktext" ] || die 'destination is a directory'
stage=$(mktemp "$dest/.masktext-install.XXXXXX")
trap 'rm -rf "$work"; rm -f "$stage"' EXIT HUP INT TERM
cat "$work/masktext" > "$stage"
chmod 755 "$stage"
mv -f "$stage" "$dest/masktext"
printf 'Installed: %s/masktext\n' "$dest"
case ":$PATH:" in *":$dest:"*) ;; *) printf 'Add this directory to PATH: %s\n' "$dest" ;; esac
