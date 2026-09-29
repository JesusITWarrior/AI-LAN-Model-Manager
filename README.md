# LAN Model Manager

LAN Model Manager is a local-first control plane for discovering, loading,
unloading, placing, and routing to AI models across authorized machines on a
LAN. It is designed around safe hot-swapping, resource-aware placement, and a
provider-neutral inventory spanning runtimes such as Ollama and LM Studio.

> **Status:** Pre-release implementation. The controller remains loopback-only.
> Authentication, pairing, authenticated agent transport, inventory, lifecycle
> policy, inference routing, artifact handling, recovery, and release-audit
> foundations are implemented and tested; native-host qualification, release
> signing, and publication are not complete.

Installation and upgrade packaging foundations are documented in [docs/operations/installation-and-upgrades.md](docs/operations/installation-and-upgrades.md). First-run trust, pairing, certificate recovery, backup, and redacted diagnostics are documented in [docs/operations/operator-console.md](docs/operations/operator-console.md).

## Architecture

- **Controller:** TypeScript API and React UI for inventory, policy, planning,
  approvals, audit history, and a separately authorized OpenAI-compatible proxy.
- **Host agent:** a small Go service for Linux, macOS, and Windows. Paired agents
  expose constrained capabilities; they are not remote shells.
- **Provider adapters:** normalize runtime-specific inventory and lifecycle
  operations. Ollama and LM Studio are first.
- **Placement engine:** rejects unsafe placements before ranking eligible hosts.
- **Artifact manager:** uses verified peer transfer first, then approved source
  download, with independent metadata and checksum verification.

See [Architecture](docs/architecture.md), [Security policy](SECURITY.md), and the
[Threat model](docs/threat-model.md).

## Development

Requirements: Node.js 24+, npm 11+, and Go 1.24+.

```bash
npm ci --ignore-scripts
make check
npm run dev:controller
```

`make check` builds the TypeScript and web projects, runs TypeScript and Go
checks, validates formatting, performs offline supply-chain checks, and runs the
source release-readiness audit. To create local **unsigned** cross-platform
package skeletons:

```bash
node scripts/packaging/build.js artifacts/host-agent
```

The development controller binds to loopback. Do not expose it publicly; the
current configuration rejects public inference binding.

## Configuration hygiene

Copy `.env.example` to `.env` for local overrides. Real addresses, machine
names, model paths, pairing keys, certificates, inventories, logs, and model
artifacts belong only in ignored local storage. Public examples use synthetic
identifiers and loopback addresses.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
