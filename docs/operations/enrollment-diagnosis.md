# Enrollment diagnosis and Windows operator presentation

## Evidence and limits

Inspected baseline `f506de89a347230e084f1ebe8ab6d2304fe3d88e` and the
running Linux controller's read-only service metadata: the installed
controller pointer is `0.1.0-alpha.5`. No live database was opened or modified.
No Windows host was available for native execution during this repair.

There is a concrete platform defect, not evidence that proof authentication
should be relaxed: `loadIdentityKey` requires POSIX mode `0600`. Go's Windows
`os.FileInfo.Mode` synthesizes `0666` for writable ordinary files (`0444` for
read-only files), independently of their NTFS DACL. Thus a previously generated,
properly ACL-protected Windows host key is rejected as corrupt and quarantined.
When no enrollment record exists, this happens during CSR preparation, before
any `/complete` proof request. An existing enrollment record instead makes
startup reject its key. Fleet rotation's generation loaders had the same
POSIX-only checks and now use the same native permission validator.

**This does not prove the cause of every clean first attempt.** A genuinely
missing key is generated and returned directly; it does not pass through the
faulty reload check on that first call. The baseline CSR construction and
self-validation agree on CN, P-256, one IP SAN and one SPIFFE URI; no separate
Windows-specific signature/URI failure was established. Native NTFS publication,
CSR generation and production service-token behavior remain acceptance tests.
New diagnostics distinguish `key`, `csr-create`, `csr-parse`, `csr-signature`
and `csr-binding` rather than guessing which combined check failed.

The misleading runtime sequence was:

1. Begin returns a code, which is printed before local CSR creation.
2. The first polling tick builds proof, then attempts key/CSR preparation.
3. A local error exits polling without sending proof. Owner confirmation can
   still succeed on the controller; it cannot manufacture the agent's proof.
4. `Service.Start` intentionally continues local observations, ignoring the
   enrollment error. Production did not wire `cfg.Log`, so its failure summary
   was never emitted. The ordinary `started` message is not enrollment success.

The repair prepares the local key/CSR before requesting/presenting a challenge,
retains the existing one-challenge pending-owner protocol, and adds redacted
local failure phases/statuses. Authentication, proof verification, owner approval,
certificate verification, expiry, retry bounds and controller rate limits are
not weakened. HTTP bodies, underlying errors, URLs, paths, codes, nonces, CSRs,
proofs and certificates are excluded from diagnostics.

## Windows code retrieval

While the service is awaiting confirmation, run the **active agent binary**
from an elevated PowerShell console (substitute its actual installed version):

```powershell
& 'C:\Program Files\LANModelManager\releases\agent\VERSION\bin\lan-model-agent.exe' --enrollment-code
```

This reads `\\.\pipe\LANModelManager-Enrollment`, not a logfile. The local-only
named pipe has a protected DACL admitting SYSTEM, built-in Administrators and
the agent process account. It rejects remote clients and a second server
instance. No code is written to disk, the registry or structured telemetry.
The reader authenticates its connected server against the SCM running
`LANModelAgent` PID, configured virtual account, process token SID, and exact
configured/running executable matching the reader binary. A lookalike pipe
server is rejected before any code is displayed. The reader uses nonblocking
reads with a three-second local deadline, independent of server input, and
identification-level SQOS prevents elevated-reader impersonation.
The channel closes on enrollment completion/failure/cancellation or the earlier
of challenge expiry and the two-minute polling deadline. Mutable code buffers
are zeroed on cleanup; abandoned pairing sessions are explicitly discarded.
Do not paste the code into issue reports. Unix console presentation remains
separate from structured telemetry; service-manager console collection is an
operator-controlled surface on that platform.

The state directory's `enrollment-status.json` holds only the latest diagnostic
outcome and observation timestamp. For the standard installer this is under
`C:\ProgramData\LANModelManager\state\agent`. An elevated administrator can
read it even when SCM does not collect stderr. It is not enrollment authority,
is not loaded to resume enrollment, and contains no operator code. `status:
"enrolled"` follows certificate verification and durable enrollment save;
`degraded` means local observation continues without enrollment. `stage` and
`reason` locate the failure; `httpStatus` is included when an HTTP response was
received (for example 429), but never its body. A timestamp identifies stale
last-run diagnostics.

**Initialization limitation:** `enrollment.New` runs during `loadConfig`, before
`cfg.Log` is installed or the service state tree is validated. Existing-key or
existing-certificate rejection at that phase returns only the generic redacted
`host-service configuration rejected` startup message (SCM may not collect it).
It does **not** update `enrollment-status.json`; any older status file remains
last-run evidence, not proof this startup enrolled. This repair intentionally
avoids writing diagnostics through an unvalidated initialization path. Native
retest must distinguish configuration/startup rejection from a completed runtime
enrollment attempt. Do not equate SCM `Running` with controller enrollment.

Private material is accepted on Windows only when its opened handle's owner and
DACL grant access to the trusted process/agent account, SYSTEM or Administrators.
Missing/null DACLs, unknown ACE forms and untrusted allowed trustees fail closed;
Unix `0600` checks are retained. The validator does not rewrite broad ACLs to
hide a containment failure. Existing explicit broad grants left in an old state
tree require an administrator to inspect and repair that installation's ACLs.

## Verification and native Windows acceptance

Linux gates: focused enrollment/service/fleet/pairing/CLI tests, real Go ↔
TypeScript pinned TLS enrollment/owner confirmation/restart fixture, race tests,
and `make check`. Windows agent and focused test binaries are cross-compiled;
cross-compilation is not native execution.

On an isolated NTFS Windows fixture, run:

```powershell
cd agents/host-agent
go test ./internal/privatefile ./internal/enrollment ./cmd/lan-model-agent
go test ./internal/service -run Enrollment
go test ./internal/fleet -run "CertificateRenewalDue|IdentityGenerationRestart"
```

Native-only tests cover restrictive-vs-Everyone-readable DACLs, Windows synthetic
mode bits, pipe exclusivity, code retrieval, cleanup and expiry. Then exercise
the installed virtual service account with a new fixture controller and an
owner: first enrollment, an existing key without public enrollment state,
confirmed enrollment, restart, fleet hello, and rotated generation reload.
Verify non-admin pipe denial separately from an elevated administrator's read;
try remote access and malformed/broad ACLs; cancel/expire before confirmation.
Inspect redacted status and assert no code/proof/certificate/private key in it.
Retain owner approval, pinned trust and proof verification throughout.

The older standalone `internal/certificate` bundle-storage helper also has
POSIX-only checks; it is not the production enrollment store or rotation loader
repaired here. Broader native Windows package-suite portability is a separate
scope; do not claim the entire Windows runtime is proven by Linux gates.

## Portable corrupt-state handling

`FileStore.Load` reads and closes its handle before parsing/quarantining corrupt
state. Windows may deny renaming the still-open handle; a deferred close was
therefore insufficient. A successful quarantine returns the recoverable
`ErrCorrupt`. Close or rename failure instead returns the bounded terminal
`ErrStateClose` or `ErrQuarantine`, without exposing an OS error/path and without
allowing `New` to treat the still-live state as permission to reenroll. Tests
exercise the original portable quarantine case, close-before-rename ordering,
and terminal failure handling without touching live state.

## Installed Windows service ImagePath and reader diagnostics

The code reader treats SCM's `BinaryPath` as a command line, not as a file path.
It requires exactly one quoted, canonical local-drive `.exe` path with no
arguments, then binds that path to both the reader executable and the running
pipe server's image. The own-process service PID, virtual account, process-token
SID, and second binding check remain mandatory. An unquoted `C:\Program Files\...`
configuration is unsafe even when SCM happens to have started the intended
binary; do not make the reader accept it or split at spaces to guess a binary.

Windows PowerShell 5.1's native argument marshalling can remove literal quotes
from `sc.exe config ... binPath= ('"{0}"' -f $binary)`. The installer now passes
`PathName`, `StartMode`, and `StartName` as typed CIM `Win32_Service.Change`
arguments instead. Create, upgrade and rollback check both the method return
value and a fresh exact path/account/start-mode readback; activation checks the
binding again before `Start-Service`. Existing unquoted installations still fail
the strict ownership preflight. This is intentional: ordinary upgrade must not
silently adopt or reinterpret an unsafe service command line.

An affected installation needs a separately owner-authorized administrator repair
of **only** the service's known exact ImagePath after confirming the expected
release binary, current service PID/image, virtual account and own-process type.
Use a typed service configuration API, preserve all other configuration, and
read back the literal outer quotes from both SCM and the raw registry. Do not
change enrollment keys, certificates, state ACLs or the reader's authentication.
A configuration repair alone does not establish enrollment or reconnect
acceptance, and does not retroactively change the running process image.

Reader failures now return a nonzero exit and a fixed bounded reason, including
`unsafe-service-image-path`, `server-authentication`, `read-timeout`, and
response/pipe stage identifiers. These messages contain no server-supplied error,
code, raw payload, path, nonce, or proof. If stdout itself cannot be written the
reader still returns nonzero; an output failure cannot carry a diagnostic.

Native safe fixtures (no SCM or registry writes):

```powershell
cd agents/host-agent
go test ./cmd/lan-model-agent -run 'Windows(ConfiguredServiceExecutable|PowerShellLegacyServiceQuoteLoss|NativeArgvProbe|PresentationAuthenticationDiagnostics|FakePresentationServerRejected|SilentPresentationServerReadIsBounded)'
cd ../..
npm run test:installer
```

The native argv fixture invokes only the test executable to reproduce the legacy
quote loss. The installer fixture extracts the two production configuration
functions and mocks both CIM commands; it exercises quote preservation, rollback,
method failures and mismatched readback. The latter is not evidence that a real
SCM configuration was changed correctly. Linux installer tests skip that native
fixture, and Windows cross-compilation is not native execution or installed
virtual-account acceptance.

## Host online but Ollama inventory missing

Enrollment/liveness success does not imply provider-inventory success. Check the
agent service's `LANMM_OLLAMA_ENDPOINT` and the read-only `/api/version` and
`/api/tags` endpoints separately. Never include private model names or raw
provider responses in tracked diagnostics or issue fixtures.

The protected state directory's `inventory-status.json` holds one latest
**outcome transition** (not a heartbeat freshness marker): `status`, `probe`,
`list`, and `observedAt`. Structured logs emit the same bounded reason codes:
`ok`, `canceled`, `timeout`, `http_status`, `response_too_large`,
`invalid_response`, or `request_failed`. Repeated identical outcomes do not
append logs or rewrite the file; a ready transition clears earlier failures.
No endpoint, model name, metadata, raw response, or transport error is retained.
A successful version probe remains visible when inventory parsing fails; models
are sent only with a successfully probed provider. Failed lists do not reuse
stale models.

Ollama `/api/tags` accepts the optional `capabilities` array and the optional
`details.context_length` / `details.embedding_length` integer fields documented
in upstream [`api/types.go`](https://github.com/ollama/ollama/blob/main/api/types.go)
(`ListModelResponse` and `ModelDetails`). These fields are bounded and validated,
not promoted to fleet capability claims. Legacy responses remain valid. Unknown
fields, duplicate keys, invalid dimensions, malformed capability arrays,
oversized bodies, and invalid model identities still fail closed. Registry-style
synthetic names such as `ollama.com/example/synthetic:latest` are supported.
This does not qualify every remote-model or manifest-runner response variant.
