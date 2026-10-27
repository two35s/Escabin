#!/bin/sh
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
dir="$HOME/.local/share/gtfobins"
target="$HOME/.local/bin/gtfobins"
mkdir -p "$dir" "$HOME/.local/bin"

if { [ -e "$target" ] || [ -L "$target" ]; } &&
   [ "$(readlink "$target" 2>/dev/null || true)" != "$dir/gtfobins" ]; then
    echo "refusing to overwrite $target (not this tool's symlink); remove it first" >&2
    exit 1
fi

install -m 755 "$here/gtfobins" "$dir/gtfobins"
ln -sf "$dir/gtfobins" "$target"
"$dir/gtfobins" update
echo "installed: $target"

case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) echo "warning: $HOME/.local/bin is not in PATH" >&2 ;;
esac
