# Installation and upgrade foundations

This slice supplies deterministic, unsigned Linux controller/host-agent and Windows host-agent package foundations. Repository builds and tests do **not** modify a live service. macOS service packaging remains a later slice.

## Hat Trick internal Alpha: one command

On the Fedora host named `Hat-Trick`, use a reviewed, clean checkout and run:

```sh
./scripts/alpha/install-hat-trick-alpha.sh
```

The command requires Node.js 24+ and the systemd user tools. It verifies the repository-relative `artifacts/alpha-final-a/lan-model-controller-linux-any.tar.gz` against both `checksums.txt` and `package-inventory.json`, then verifies the package's bounded install manifest and every payload byte before changing the installation. It installs versioned files under `${XDG_DATA_HOME:-$HOME/.local/share}/lan-model-manager-alpha`, keeps controller state separately under `${XDG_STATE_HOME:-$HOME/.local/state}/lan-model-manager-alpha/controller`, and creates only a `systemctl --user` service. Re-running the command is idempotent; a newer verified package switches releases while preserving state and rolls back if `/auth/v1/status` is not healthy.

This is an **unsigned internal Alpha**. SHA-256 verification detects corruption but does not establish publisher authenticity. The service binds only `127.0.0.1:7340` and `127.0.0.1:7341`; discovery and public inference are disabled. TLS is deliberately disabled only for this loopback-only Alpha. The installer makes no firewall, system-service, `/opt`, `/etc`, Ollama, model, or hosted-workflow changes.

Preview without installing:

```sh
./scripts/alpha/install-hat-trick-alpha.sh --dry-run
```

Remove the user service and installed program files while retaining controller state:

```sh
./scripts/alpha/uninstall-hat-trick-alpha.sh
```

Use `--dry-run` to preview removal. Only an intentional `--purge` removes the preserved controller state, after a destructive warning.

Current Alpha limitation: the packaged controller console is available, but the complete packaged pairing/provider flow is not yet composed. Treat installation success as controller-service readiness, not end-to-end host/model readiness.

## Package trust and inventory

`scripts/packaging/build.js` cross-builds the host agent and packages the compiled Linux controller plus web assets. Every archive is reproducible: tar metadata and gzip timestamps are fixed, entries are ordered, and Go builds use `-trimpath`, `-buildvcs=false`, and `CGO_ENABLED=0`. Each package contains `install/install-manifest.json` with an allowlisted role/version, per-file size, mode, SHA-256, source commit, deterministic inventory digest, and explicit `unsigned: true` provenance. The output directory also contains:

- `checksums.txt`, binding each archive name to SHA-256;
- `package-inventory.json`, binding role, target, size, archive digest, inventory digest, and source commit;
- package file components when that inventory is passed to `scripts/packaging/sbom.js` as its fourth argument.

Signing remains closed. Unsigned metadata is provenance, not authenticity; obtain packages over a trusted channel and verify the independently published checksum before extraction. Packaging rejects a dirty source tree by default; `LAN_ALLOW_DIRTY=1` exists only for explicit local fixture builds and must not be used for release artifacts.

## Canonical locations and identities

| Purpose | Linux | Windows |
| --- | --- | --- |
| versioned releases | `/opt/lan-model-manager/releases/<role>/<version>` | `%ProgramFiles%\LANModelManager\releases\<role>\<version>` |
| persistent state and enrollment material | `/var/lib/lan-model-manager/<role>` | `%ProgramData%\LANModelManager\state\<role>` |
| configuration | `/etc/lan-model-manager/<role>` | `%ProgramData%\LANModelManager\config\<role>` |
| logs | `/var/log/lan-model-manager` | `%ProgramData%\LANModelManager\log` |

Linux definitions use locked, non-login `lanmodel-controller` and `lanmodel-agent` accounts declared through `sysusers.d`, strict state/config modes through `tmpfiles.d`, and hardened systemd units. Windows uses service virtual accounts (`NT SERVICE\LANModelController` and `NT SERVICE\LANModelAgent`) and explicit ACLs. The Windows script makes no firewall change. Both platforms leave services disabled and stopped after creation.

## Rootless validation and dry run

Extract a package into a private directory, then run the installer against a fixture root. Inputs are separate arguments; role, version, platform, manifest paths, and every payload path are validated rather than evaluated by a shell.

```sh
node scripts/install/cli.js install \
  --platform linux --root "$PWD/.install-fixture" --dry-run \
  --payload "$PWD/extracted" \
  --manifest "$PWD/extracted/install/install-manifest.json"
```

Dry run still reads every payload file and verifies its size, SHA-256, complete inventory digest, and source provenance. It makes no directory or service-definition change.

## Upgrade transaction

The library entrypoint `installRelease()` implements the transaction used by native entrypoints:

1. Validate bounded role/version/path grammar and the provenance record.
2. Verify every payload byte before any mutation.
3. Copy into a unique staging directory under the canonical release root.
4. Write the immutable install manifest, then rename staging to the versioned release.
5. Atomically replace the role's current-version pointer.
6. Invoke an explicitly supplied service-restart adapter, then an explicitly supplied health check.
7. If restart or health fails, restore the previous pointer and restart that previous release.

Tests inject adapters; they never call a service manager. Versions remain side-by-side for deterministic rollback and interrupted staging is removed. Enrollment keys, certificates, databases, and other state live outside release directories and are never copied over during upgrade.

The Windows host-agent binary implements the native Service Control Manager dispatcher and stop/shutdown controls; interactive launch falls back to console signal handling. `Install-LANModelService.ps1` accepts only validated role/version/action values, creates a disabled service, refuses to reconfigure a running service, binds its canonical state/certificate/cache environment, applies virtual-account ACLs, and supports `-WhatIf`. It leaves the service disabled and stopped unless the operator explicitly supplies `-Activate`; activation performs a bounded running-state health check and restores the prior SCM binary path on failure. The Linux package includes systemd/sysusers/tmpfiles definitions but build and fixture paths never invoke `systemctl`, `systemd-sysusers`, or `systemd-tmpfiles`. Packaged JS installer entrypoints require Node.js 24 or newer.

## Uninstall and recovery

```sh
node scripts/install/cli.js uninstall --platform linux --root "$fixture" --role agent --dry-run
```

Normal uninstall removes release pointers, versioned program files, and generated service definitions while preserving state and configuration. Add `--purge` only for an intentional destructive removal of enrollment material and configuration. The PowerShell uninstall similarly refuses to delete a running service and preserves data unless `-Purge` is present.

If an upgrade reports rollback, inspect the staged release's manifest and logs; the previous pointer is already restored. Do not delete the preserved state directory. A later retry can reuse the same package only after its checksum and provenance have been verified again.
