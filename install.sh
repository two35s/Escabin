#!/bin/sh
set -eu

raw="https://raw.githubusercontent.com/two35s/Escabin/main"
dir="$HOME/.local/share/gtfobins"
target="$HOME/.local/bin/gtfobins"
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
tmp=""

cleanup() {
    [ -z "$tmp" ] || rm -f "$tmp"
}
trap cleanup 0

mkdir -p "$dir" "$HOME/.local/bin"

if { [ -e "$target" ] || [ -L "$target" ]; } &&
   [ "$(readlink "$target" 2>/dev/null || true)" != "$dir/gtfobins" ]; then
    echo "refusing to overwrite $target (not this tool's symlink); remove it first" >&2
    exit 1
fi

if [ -f "$here/gtfobins" ]; then
    src="$here/gtfobins"
else
    command -v curl >/dev/null 2>&1 || {
        echo "curl is required for a remote install" >&2
        exit 1
    }
    tmp=$(mktemp "${TMPDIR:-/tmp}/gtfobins.XXXXXX")
    curl -fsSL "$raw/gtfobins" -o "$tmp"
    [ -s "$tmp" ] || {
        echo "download failed: empty file" >&2
        exit 1
    }
    src="$tmp"
fi

install -m 755 "$src" "$dir/gtfobins"
ln -sf "$dir/gtfobins" "$target"
if ! "$dir/gtfobins" update; then
    echo "warning: could not update data; run 'gtfobins update' later" >&2
fi
echo "installed: $target"

case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) echo "warning: $HOME/.local/bin is not in PATH" >&2 ;;
esac
