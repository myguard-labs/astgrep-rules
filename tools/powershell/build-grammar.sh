#!/usr/bin/env bash
# Build the pinned PowerShell tree-sitter grammar into a loadable dynamic library.
#
# Deterministic by construction: the source is a specific upstream commit whose
# tarball checksum is verified before a single byte is compiled. A checksum
# mismatch is fatal -- we never build an unverified parser, because ast-grep
# loads it as native code and a substituted grammar silently changes which
# security findings are reported.
#
# Usage: tools/powershell/build-grammar.sh [output-path]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
lock="$here/grammar.lock.json"

read_lock() { python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['grammar'][sys.argv[2]])" "$lock" "$1"; }

repo="$(read_lock repository)"
tag="$(read_lock tag)"
commit="$(read_lock commit)"
symbol="$(read_lock symbol)"

# Library extension per platform. ast-grep resolves the library through the
# host dynamic loader, so the suffix must be the platform-native one.
case "$(uname -s)" in
  Darwin)            ext=dylib ;;
  MINGW*|MSYS*|CYGWIN*|Windows_NT) ext=dll ;;
  *)                 ext=so ;;
esac

out="${1:-$root/build/powershell/powershell.$ext}"
mkdir -p "$(dirname "$out")"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

tarball="$work/grammar.tar.gz"
# Fetch by immutable commit, not by tag: a tag can be moved, a commit cannot.
url="$repo/archive/$commit.tar.gz"
echo "==> fetching $repo @ $tag ($commit)"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$url" -o "$tarball"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$tarball" "$url"
else
  echo "error: neither curl nor wget is available" >&2
  exit 1
fi

src="$work/src"
mkdir -p "$src"
tar xzf "$tarball" -C "$src" --strip-components=1

# Verify the compiled sources by content, not the tarball: GitHub's archive
# bytes are not stable over time, but the file contents at a fixed commit are.
echo "==> verifying source checksums"
sha_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}
while IFS='|' read -r rel want; do
  [ -n "$rel" ] || continue
  if [ ! -f "$src/$rel" ]; then
    echo "error: pinned source $rel missing from upstream archive" >&2
    exit 1
  fi
  got="$(sha_of "$src/$rel")"
  if [ "$got" != "$want" ]; then
    echo "error: checksum mismatch for $rel" >&2
    echo "  expected $want" >&2
    echo "  actual   $got" >&2
    echo "refusing to build an unverified parser" >&2
    exit 1
  fi
  echo "    ok $rel"
done < <(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))['grammar']['sourceSha256']
for k,v in d.items(): print(k+'|'+v)
" "$lock")


echo "==> compiling $out"
cc_bin="${CC:-cc}"
"$cc_bin" -shared -fPIC -O2 \
  -I "$src/src" \
  -o "$out" \
  "$src/src/parser.c" "$src/src/scanner.c"

# A library that does not export the entry point loads but yields zero matches,
# which is indistinguishable from "the code is clean". Fail loudly instead.
if command -v nm >/dev/null 2>&1; then
  if ! nm -D "$out" 2>/dev/null | grep -q " T $symbol$" \
     && ! nm -g "$out" 2>/dev/null | grep -q "$symbol"; then
    echo "error: $out does not export $symbol" >&2
    exit 1
  fi
fi

echo "==> built $out"
