#!/bin/sh
set -eu
usage(){ echo 'usage: Install-LANModelService.sh install|upgrade|uninstall --role controller|agent [--payload DIR --manifest FILE] [--root DIR] [--dry-run] [--purge]' >&2; exit 64; }
[ "$#" -ge 1 ] || usage
action=$1; shift
role= payload= manifest= root=/ dry_run= purge=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --role) [ "$#" -ge 2 ] || usage; role=$2; shift 2;;
    --payload) [ "$#" -ge 2 ] || usage; payload=$2; shift 2;;
    --manifest) [ "$#" -ge 2 ] || usage; manifest=$2; shift 2;;
    --root) [ "$#" -ge 2 ] || usage; root=$2; shift 2;;
    --dry-run) dry_run=--dry-run; shift;;
    --purge) purge=--purge; shift;;
    *) usage;;
  esac
done
case "$action" in install|upgrade|uninstall) ;; *) usage;; esac
case "$role" in controller|agent) ;; *) usage;; esac
case "$root" in /*) ;; *) usage;; esac
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
if [ "$action" = uninstall ]; then
  if [ "$root" = / ] && [ -z "$dry_run" ]; then
    unit="lan-model-$role.service"
    if systemctl is-active --quiet "$unit" || systemctl is-enabled --quiet "$unit"; then echo 'ERR_SERVICE_ACTIVE_OR_ENABLED' >&2; exit 69; fi
  fi
  node "$script_dir/cli.js" uninstall --platform linux --root "$root" --role "$role" ${dry_run:+"$dry_run"} ${purge:+"$purge"}
else
  [ -n "$payload" ] && [ -n "$manifest" ] || usage
  node "$script_dir/cli.js" "$action" --platform linux --root "$root" --role "$role" --payload "$payload" --manifest "$manifest" ${dry_run:+"$dry_run"}
fi
# Account and directory declarations are applied only for a real host-root install.
# No service is enabled, started, stopped, or restarted here.
if [ "$root" = / ] && [ -z "$dry_run" ] && [ "$action" != uninstall ]; then
  systemd-sysusers /usr/lib/sysusers.d/lan-model-manager.conf
  systemd-tmpfiles --create /usr/lib/tmpfiles.d/lan-model-manager.conf
fi
