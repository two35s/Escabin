#!/bin/sh
set -eu

raw="https://raw.githubusercontent.com/two35s/Escabin/main"
dir="$HOME/.local/share/escabin"
target="$HOME/.local/bin/escabin"
tmp=""
staged=""

cleanup() {
    [ -z "$tmp" ] || rm -f "$tmp"
    [ -z "$staged" ] || rm -f "$staged"
}
trap cleanup 0

mkdir -p "$dir" "$HOME/.local/bin"

command -v python3 >/dev/null 2>&1 || {
    echo "python3 is required" >&2
    exit 1
}
if ! python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 7))' 2>/dev/null; then
    echo "python3 3.7 or newer is required" >&2
    exit 1
fi

if { [ -e "$target" ] || [ -L "$target" ]; } &&
   [ "$(readlink "$target" 2>/dev/null || true)" != "$dir/escabin" ]; then
    echo "refusing to overwrite $target (not this tool's symlink); remove it first" >&2
    exit 1
fi

# Use a local checkout only when this really is the repo's install.sh; when the
# script is piped to sh, $0 is "sh" and a file named escabin in the cwd must not
# be installed by accident. tests.py is a cheap marker for a full checkout.
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
local_src=""
if [ "$(basename "$0")" = "install.sh" ] && [ -f "$here/escabin" ] &&
   [ -f "$here/tests.py" ]; then
    local_src="$here/escabin"
fi

if [ -n "$local_src" ]; then
    src="$local_src"
else
    command -v curl >/dev/null 2>&1 || {
        echo "curl is required for a remote install" >&2
        exit 1
    }
    tmp=$(mktemp "${TMPDIR:-/tmp}/escabin.XXXXXX")
    if ! curl -fsSL --connect-timeout 10 --max-time 120 -o "$tmp" "$raw/escabin"; then
        echo "download failed: $raw/escabin" >&2
        exit 1
    fi
    [ -s "$tmp" ] || {
        echo "download failed: empty file" >&2
        exit 1
    }
    src="$tmp"
fi

staged="$dir/.escabin.new.$$"
install -m 755 "$src" "$staged"
if ! "$staged" --version >/dev/null 2>&1; then
    echo "refusing to install: the new escabin does not run" >&2
    exit 1
fi
mv -f "$staged" "$dir/escabin"
staged=""
ln -sf "$dir/escabin" "$target"
if ! "$dir/escabin" update; then
    echo "warning: could not update data; run 'escabin update' later" >&2
fi
echo "installed: $target"

case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) echo "warning: $HOME/.local/bin is not in PATH" >&2 ;;
esac
