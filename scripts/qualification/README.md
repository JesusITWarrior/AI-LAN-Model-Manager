# Offline postpublication overlay qualification

Linux host only; Python 3.12+ standard library, Git, and an already installed local
Go toolchain with race support are required. No dependency/toolchain fetching is
permitted. Run from a checkout, explicitly naming the full accepted commit:

```sh
python3 scripts/qualification/native-postpublication-overlay.py --commit d65ecf612403a792034d3e94ed9eae4739c5b939
```

The caller attests that the exact commit is accepted; the driver does not infer
acceptance from a branch or mutable checkout. Dirty checkouts are allowed and
recorded, never incorporated: the entire immutable commit is git-archived into a
fresh ignored `config/private/continuation/native-overlay-driver-*` directory
(mode 0700). The driver and exact hash-pinned fixture are read from this checkout,
so the accepted archive need not yet contain this driver. Wrong fixture bytes,
noncanonical writer span, duplicate fixture, non-full commit, non-Linux host, or
nonignored output location fail explicitly (also under Python `-O`).

Only scratch overlay files change: exactly one writer-body span replaces the
post-Rename finish callback with existing `ErrReplayPersistence`; the other
mapping appends the exact proven fixture bytes to the archived lifetime test.
Actual archived Go source is not edited, and its hashes are reverified afterward.
The driver runs the anchored overlay race test count=3 with Go timeout=90s,
then unmodified command/fleet/main race count=3 and `go vet ./...`. Each subprocess
has a bounded outer timeout and its process group is killed/joined on interruption
or timeout. GOENV/GOWORK/GOPROXY/GOSUMDB are off, GOTOOLCHAIN is local, GOFLAGS
is empty and GOOS is linux. No Windows execution or live operations occur.

Artifacts retain commit/tree/archive hashes, exact inputs/generated file hashes,
recipe, effective Go environment, commands, logs and terminal status. Review the
printed artifact path. No full-project gates, commit or push are performed.

This is a synthetic signed in-memory RoundTripper and in-process sequential
Run/Quiesce handoff regression. It exercises real file publication/Rename followed
by an injected finish failure; it is not a real filesystem failure reproduction,
network TLS/native installed-agent qualification, separate expiry test, restart
recovery, crash/power-loss durability proof, transfer or model API test. The
injected callback bypasses actual finish/directory sync. Parent independent review
and full project gates remain necessary; this repository test driver adds no
production hook, fault setter, runtime flag, dependency or protocol behavior.
