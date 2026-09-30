#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
command -v node >/dev/null 2>&1 || { echo 'ERROR: Node.js 24 or newer is required.' >&2; exit 69; }
node_major=$(node -p 'Number(process.versions.node.split(".")[0])')
[ "$node_major" -ge 24 ] || { echo 'ERROR: Node.js 24 or newer is required.' >&2; exit 69; }
command -v systemctl >/dev/null 2>&1 || { echo 'ERROR: systemd user tools are required.' >&2; exit 69; }
exec node "$script_dir/fedora-alpha.mjs" install "$@"
