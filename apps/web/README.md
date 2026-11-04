# Web application

React operator console for the versioned `/api/v1` management surface.

- `npm run build -w @lan-model-manager/web` creates the production bundle.
- The development server binds loopback on port 4173 and proxies `/api` to the loopback controller.
- Owner lifecycle proposals and Settings mutations require authenticated owner requests and CSRF; lifecycle execution remains explicitly reviewed.

The client consumes strict public DTOs. Issued inference credentials are displayed once in component memory until acknowledgment, never persisted by Settings. Errors do not echo raw controller exceptions or secrets.

## Offline mounted browser gates

`CHROMIUM_PATH=/path/to/chromium npm test -w @lan-model-manager/web` runs the real mounted React lifecycle and settings fixtures with the locally available Chromium executable (default `/usr/bin/chromium-browser`). Node 24, installed lockfile dependencies and that browser are prerequisites; no browser downloads, provider connections or live databases are used. Missing Chromium fails the gate rather than skipping it. Each test owns a temporary profile/listener and cleans it up.

Settings offers explicit constrained policy saves and token lifecycle actions. Only inference and load/drain/unload permissions are editable in the bounded owner editor; all other existing operations and server-owned safety flags are retained. The API understands all twelve core operation names. Readiness is deliberately unknown where the browser cannot prove admission and policy/trust; token metadata and inventory are not connectivity tests. The default local inference base URL is `http://127.0.0.1:7341/v1` (verify the configured listener). Listing models is not proof of chat eligibility. Never put a bearer token in a URL or disable TLS verification.

Both `POST /api/v1/policy/settings` and `POST /api/v1/policy/convenience` require the reviewed `expectedVersion`. Convenience accepts exactly `{enabled: boolean, expectedVersion: number}`; old `{enabled}` callers now fail with 400 (no legacy bypass). A stale version returns 409 without policy/audit changes; reload and review before confirming again. Policy increments stop at `Number.MAX_SAFE_INTEGER`; that final version remains readable but cannot be incremented. One synchronous Settings mutation gate covers editor saves, no-prompt, issuance and all token revocations; clipboard copying is local and independent, and issued secrets remain until acknowledgment.
