#!/bin/sh
set -eu

raw="https://raw.githubusercontent.com/two35s/Escabin/main"
dir="$HOME/.local/share/escabin"
target="$HOME/.local/bin/escabin"
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
tmp=""

cleanup() {
    [ -z "$tmp" ] || rm -f "$tmp"
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

if [ -f "$here/escabin" ]; then
    src="$here/escabin"
else
    command -v curl >/dev/null 2>&1 || {
        echo "curl is required for a remote install" >&2
        exit 1
    }
    tmp=$(mktemp "${TMPDIR:-/tmp}/escabin.XXXXXX")
    curl -fsSL "$raw/escabin" -o "$tmp"
    [ -s "$tmp" ] || {
        echo "download failed: empty file" >&2
        exit 1
    }
    src="$tmp"
fi

install -m 755 "$src" "$dir/escabin"
ln -sf "$dir/escabin" "$target"
if ! "$dir/escabin" update; then
    echo "warning: could not update data; run 'escabin update' later" >&2
fi
echo "installed: $target"

case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) echo "warning: $HOME/.local/bin is not in PATH" >&2 ;;
esac
