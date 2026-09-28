# Web application

React operator console for the versioned `/api/v1` management surface.

- `npm run build -w @lan-model-manager/web` creates the production bundle.
- The development server binds loopback on port 4173 and proxies `/api` to the loopback controller.
- Fleet, Models, Operations, and Settings are read-only in P9.1. Mutating controls remain out of scope until the approval UX is wired end to end.

The client consumes redacted public response envelopes only; it does not model certificates, tokens, digests, private endpoints, or persisted snapshots.
