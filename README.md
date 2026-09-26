# LAN Model Manager

LAN Model Manager is a local-first control plane for discovering, loading,
unloading, placing, and routing to AI models across authorized machines on a
LAN. It is designed around safe hot-swapping, resource-aware placement, and a
provider-neutral inventory spanning runtimes such as Ollama and LM Studio.

> **Project status:** architecture and safety foundation. No host mutation or
> inference proxy is enabled yet.

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

See [Architecture](docs/architecture.md), [Security](SECURITY.md), and the
[Roadmap](docs/roadmap.md).

## Development

Requirements: Node.js 24+, npm 11+, and eventually Go 1.24+ for host-agent work.

```bash
npm install
npm run check
npm run dev:controller
```

The development controller binds to loopback by default. Do not expose it to a
LAN until authenticated transport and owner setup are implemented.

## Configuration hygiene

Copy `.env.example` to `.env` for local overrides. Real addresses, machine
names, model paths, pairing keys, certificates, inventories, logs, and model
artifacts belong only in ignored local storage. Public examples use synthetic
identifiers and loopback addresses.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
