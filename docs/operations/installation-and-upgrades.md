# Installation and upgrade foundations

This slice supplies deterministic, unsigned Linux controller/host-agent and Windows host-agent package foundations. Repository builds and tests do **not** modify a live service. macOS service packaging remains a later slice.

## Internal Fedora Alpha: one command

On an approved Fedora Alpha qualification host, use a reviewed, clean checkout and run:

```sh
./scripts/alpha/install-fedora-alpha.sh
```

The command requires Node.js 24+ and the systemd user tools. It verifies the repository-relative `artifacts/alpha-final-a/lan-model-controller-linux-any.tar.gz` against both `checksums.txt` and `package-inventory.json`, then verifies the package's bounded install manifest and every payload byte before changing the installation. It installs versioned files under `${XDG_DATA_HOME:-$HOME/.local/share}/lan-model-manager-alpha`, keeps controller state separately under `${XDG_STATE_HOME:-$HOME/.local/state}/lan-model-manager-alpha/controller`, and creates only a `systemctl --user` service. Re-running the command is idempotent; a newer verified package switches releases while preserving state and rolls back if `/auth/v1/status` is not healthy.

This is an **unsigned internal Alpha**. SHA-256 verification detects corruption but does not establish publisher authenticity. By default the service binds only `127.0.0.1:7340` and `127.0.0.1:7341`; discovery and public inference are disabled. TLS is deliberately disabled only for those loopback-only surfaces. The installer makes no firewall, system-service, `/opt`, `/etc`, Ollama, model, or hosted-workflow changes.

To opt into the separate TLS 1.3 agent plane on one canonical RFC 1918 address while keeping the console and inference listeners loopback-only, pass the host's selected private address. The optional port defaults to `7443` and never changes firewall policy:

```sh
./scripts/alpha/install-fedora-alpha.sh \
  --agent-plane-address 192.168.50.10 \
  --agent-plane-port 7443
```

Preview without installing:

```sh
./scripts/alpha/install-fedora-alpha.sh --dry-run
```

Remove the user service and installed program files while retaining controller state:

```sh
./scripts/alpha/uninstall-fedora-alpha.sh
```

Use `--dry-run` to preview removal. Only an intentional `--purge` removes the preserved controller state, after a destructive warning.

The opt-in agent plane composes discovery, CA-pinned enrollment, mTLS fleet heartbeat, and command polling. Installation health still proves controller readiness only; end-to-end readiness additionally requires an enrolled host agent and a verified provider inventory.

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

The Windows package provides matched `Install-LANModelAgent.ps1` and `Uninstall-LANModelAgent.ps1` entrypoints for Windows PowerShell 5.1 or newer. Run the installer from the extracted package with `-Version <package-version> -WhatIf` first; omit `-WhatIf` and add `-Activate` only after reviewing the plan. The entrypoint verifies every package byte and provenance record through the packaged Node.js installer before configuring SCM. Its bounded `Install-LANModelService.ps1` helper creates a disabled service, refuses to reconfigure a running service, binds canonical state/certificate/cache environment variables, applies virtual-account ACLs, and changes no firewall rule. Activation performs a bounded running-state health check and restores the prior SCM binary path on failure. The Linux package includes systemd/sysusers/tmpfiles definitions but build and fixture paths never invoke `systemctl`, `systemd-sysusers`, or `systemd-tmpfiles`. Packaged installer entrypoints require Node.js 24 or newer.

## Uninstall and recovery

```sh
node scripts/install/cli.js uninstall --platform linux --root "$fixture" --role agent --dry-run
```

Normal uninstall removes release pointers, versioned program files, and generated service definitions while preserving state and configuration. Add `--purge` only for an intentional destructive removal of enrollment material and configuration. On Windows, run `Uninstall-LANModelAgent.ps1 -WhatIf` first, then run it without `-WhatIf`; add `-Purge` only for intentional destruction of enrollment state and configuration. The uninstaller refuses to delete a running service and never touches unrelated providers, models, firewall rules, or user data.

If an upgrade reports rollback, inspect the staged release's manifest and logs; the previous pointer is already restored. Do not delete the preserved state directory. A later retry can reuse the same package only after its checksum and provenance have been verified again.

## Private-LAN agent plane

Production controller deployments can enable a second listener with `LANMM_AGENT_PLANE_ENABLED=true`, an exact IPv4 bind in `LANMM_AGENT_PLANE_HOST` (or `0.0.0.0`), the exact LAN IPv4 certificate identity in `LANMM_AGENT_PLANE_ADVERTISED_ADDRESS`, and `LANMM_AGENT_PLANE_PORT`. The operator console and inference listeners remain restricted to loopback. The agent plane is TLS 1.3 only: enrollment is authenticated by the separately supplied CA certificate and SHA-256 pin; fleet heartbeat and command routes additionally require an active client certificate and signed replay-protected envelope. Enabling the plane requires discovery. The controller creates no firewall rule.

The Windows agent installer requires the controller HTTPS URL, public CA certificate file, CA fingerprint, candidate IPv4 address, and advertised protocol port. It copies only the public CA certificate into the protected service configuration, configures outbound enrollment/fleet traffic and sender-only mDNS advertisements, and observes loopback Ollama. It creates no inbound listener and makes no firewall change. The advertised port is protocol binding metadata for pairing; it does not cause the agent to listen on that port.

### Agent-plane certificate lifecycle and rollback

The controller stores each server-certificate generation in a non-symlink generation directory and activates it with one fsynced pointer rename. Generation and OpenSSL validation failures leave the previous generation selected. Certificates are renewed seven days before their 30-day expiry and the live TLS server reloads the new context on a twelve-hour maintenance interval.

Host certificates use the same seven-day renewal threshold. The Windows/Linux agent checks at startup and every twelve hours, creates a durable pending CSR before contacting the controller, and activates the returned key/certificate/enrollment bundle with one fsynced generation pointer. The controller's rotation is authenticated by the currently enrolled client certificate. If interruption occurs after controller-side replacement, that revoked predecessor may only recover the already-issued successor whose public key exactly matches the durable pending CSR; it cannot request a different identity. This makes restart recovery bounded without reopening general access for revoked certificates.

Windows service installation validates all private IPv4, URL, fingerprint, display-name, CA, reparse-point, and port inputs again inside the privileged service script. Package-pointer, service path/start mode, registry environment, copied public CA, and newly created service state are restored or removed on failure. The installer and service scripts still create no firewall rules.

If a host certificate has already expired or was deliberately revoked without a recoverable pending rotation, revoke its still-active controller record first, then stop the Windows service and rerun the verified agent installer with `-ReEnroll` (and normally `-Activate`). The privileged script writes a protected one-shot marker transactionally. On startup the agent atomically archives the old certificate directory, consumes the marker, advertises a fresh candidate, and requires the controller owner to confirm the new pairing code. The archived identity is retained for forensic recovery and is never reused automatically.
