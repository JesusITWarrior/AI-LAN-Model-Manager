#!/bin/sh
set -eu
role=${1-}
case "$role" in controller|agent) ;; *) echo 'ERR_INSTALL_ROLE' >&2; exit 64;; esac
base=/opt/lan-model-manager
version=$(cat "$base/$role.current")
case "$version" in *[!0-9A-Za-z.-]*|*..*|'') echo 'ERR_INSTALL_VERSION' >&2; exit 65;; esac
case "$role" in controller) exec "$base/releases/controller/$version/bin/lan-model-controller";; agent) exec "$base/releases/agent/$version/bin/lan-model-agent";; esac
