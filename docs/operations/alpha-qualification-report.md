# Phase 18.13 Alpha qualification report

**Qualification date:** 2026-09-29 (America/Chicago)

**Base commit at qualification start:** `619e29a76df4c2a8ab40e333a2a699e016e2e7a1`

**Post-repair candidate commit:** `3e131b115c336aea60ab969044f8732823cd6e37` (remote-verified)

**Scope:** qualification and fixable-gap repair only; no production deployment

**Verdict:** **NO-SHIP**

The implementation has strong loopback, cross-language, packaging, recovery, and rootless-install evidence. Three in-repository qualification defects were repaired, reviewed, committed at `3e131b1`, and all available local gates pass. Clean-source package bytes were rebuilt twice at that exact commit and matched. Release shipment remains blocked because packages are unsigned, PowerShell 7.2 (`pwsh`) was unavailable on Windows qualification host for the required native `-WhatIf` service-script run, and no real installed service or native two-host lifecycle/chat drill was performed. No service, host configuration, firewall rule, hosted workflow, or unrelated runtime was changed.

## Hosts and tools

### Linux qualification host

- Host label: redacted internal Linux qualification host
- OS/kernel: Fedora Linux 43 Workstation; Linux `7.2.7-100.fc43.x86_64`, x86_64
- Node.js `v24.21.0`; npm `11.19.0`
- Go `go1.26.8 linux/amd64`
- Git `2.55.0`; GNU Make `4.4.1`; Python `3.14.7`
- Candidate checkout began clean at `619e29a76df4c2a8ab40e333a2a699e016e2e7a1`, exactly matching `origin/main`.

### Windows qualification host

- Host/node labels and control-plane identifiers: redacted
- OS: Microsoft Windows `10.0.26200.9550`, amd64
- Node.js `v24.21.0`; npm `12.1.0`; Git `2.54.0.windows.1`
- Windows PowerShell `5.1.26100.9549`
- **Missing:** PowerShell 7.2+ (`pwsh`) and Go on PATH or in the searched standard/user locations
- Qualification used a disposable detached checkout under the tester's user profile, pinned to the base commit; it and its fixtures were removed after evidence collection.
- Disposable package/root fixtures only; no SCM service, registry service environment, Program Files installation, ProgramData production state, firewall rule, or host configuration was created or changed.

## Requirements-to-evidence matrix

| Alpha requirement | Evidence executed | Result | Residual gap / blocker |
|---|---|---:|---|
| Clean checkout and complete project gate | Removed workspace `node_modules`, ran `npm ci --ignore-scripts`, then `make check` from clean base. Build passed; TypeScript/core/controller: 589/589; Go packages: 16/16; supply-chain: 25/25; release audit: `release-readiness:ok`. | PASS | The repaired candidate is committed and remote-verified. Post-repair `make check` passed, followed by a clean-source reproducible package double-build at exact commit `3e131b1`. |
| Reproducible package double build | Ran `node scripts/packaging/build.js artifacts/alpha-repro` twice from the clean base, removed output between builds, hashed every output, and compared 9 hash rows. All bytes matched. `sha256sum -c checksums.txt` passed for all seven archives. | PASS (base commit) | Clean-source repaired packages were rebuilt twice at `3e131b1`; all nine generated output hashes matched and all seven archive checksums verified. |
| Linux rootless install / uninstall | Extracted the clean Linux amd64 archive into `/tmp`, ran installer dry-run and verified no root mutation, performed actual install under a disposable root, executed the installed binary for 3 seconds, verified invalid enrollment configuration exits 2 without leaking the canary endpoint, then uninstalled and verified enrollment-state sentinel preservation. | PASS | Native system package/service activation was intentionally not performed. |
| Linux upgrade / rollback | `scripts/install/tests/core.test.ts` performed side-by-side upgrade, injected failed health, restored pointer, restarted previous release through an injected adapter, and preserved enrollment state. Repeated in full/supply-chain gates. | PASS (fixture) | No systemd invocation or actual service restart, by safety boundary. |
| Native Linux package binary smoke | Packaged amd64 binary launched from rootless install; graceful TERM path was exercised via `timeout`; invalid-config output was redacted. | PASS | Package from the base commit lacked a useful CLI help mode; repaired in the working tree and proved on native Windows. |
| Windows package extraction and amd64 binary | Transferred the repaired unsigned Windows amd64 fixture archive to the isolated qualification host, extracted with native `tar.exe`, ran `lan-model-agent.exe --help` and `--version`, and exercised invalid `LANMM_UNKNOWN=TOP_SECRET_CANARY`. Help/version exited successfully; invalid startup exited 2 with only `invalid service configuration`. | PASS | Native Windows qualification host proof used the pre-commit qualification fixture; equivalent packages were subsequently rebuilt reproducibly from clean commit `3e131b1`. Artifacts remain unsigned and are not release artifacts. |
| Windows rootless install / uninstall | Native Node ran package `install/cli.js` with `--platform windows` against a user fixture root: dry-run, actual install, state sentinel creation, uninstall, and state-preservation verification all passed. | PASS | No real Program Files/ProgramData or SCM mutation. |
| Windows upgrade / rollback fixture | The native Windows qualification host ran `npm run test:installer`: initial run found two test portability defects; after repair, 9/9 passed, including Windows pointer rollback and enrollment-state preservation. | PASS after repair | Fixture only; no live service restart. |
| Windows service PowerShell parse / `-WhatIf` | The qualification host's Windows PowerShell parser read the packaged script with zero parse errors (`tokens=651`). Script source was also checked for disabled startup, virtual service account, bounded environment, rollback, and no firewall changes. | PARTIAL | **BLOCKER:** script declares `#Requires -Version 7.2`; The Windows qualification host has only Windows PowerShell 5.1 and no `pwsh`. A truthful native PowerShell 7.2 `-WhatIf` run was impossible. It was not bypassed and no service was created. |
| Enrollment and restart | `enrollment-cross-language.test.ts` repeatedly launched a real TypeScript TLS enrollment handler and Go client helper, persisted key/certificate material, and restarted without reenrollment. | PASS (two-process loopback) | No physical Linux qualification host-to-Windows qualification host pairing through the production UI. |
| mTLS heartbeat and revocation | `fleet-agent-cross-language.test.ts` repeatedly drove Go enrollment into real TypeScript mTLS hello/heartbeat inventory, restart sequence, replay state, and certificate-revocation rejection. Transport tests also verified real certificate trust/revocation. | PASS (two-process loopback) | No Windows sleep/resume or real LAN outage/reconnect drill. |
| Typed command channel and restart | Controller `agent-command-channel`/`command-dispatch` coverage plus Go command tests exercised signed envelopes, binding, replay, cancellation, progress/result durability, restart, and redacted errors. | PASS (cross-language components) | No physical two-host crash/reconnect command against a real provider. |
| Remote chat and lifecycle | `inference-chat`, `inference-agent-transport`, `remote-lifecycle`, lifecycle-service, and Go Ollama/LM Studio provider tests covered queueing, streaming/cancellation, load/readback, drain-before-unload, leases, stale state, and provider convergence with loopback/fake providers. | PASS (safe fixture) | No packaged native Windows qualification host load→chat→drain→unload against its real Ollama; avoided to prevent unrelated model/runtime mutation. |
| Artifact delivery and peer transfer | `artifact-install-cross-language.test.ts` ran a real TS mTLS delivery through the Go agent to a loopback Ollama fixture. `artifact-transfer.test.ts` and Go fleet helpers ran signed ticket, exact chunk, restart/resume, digest, quarantine, lease, ACK-crash-window, and commit-receipt paths. | PASS (two-process loopback) | No large real model transfer between physical hosts. |
| Backup export, preflight, restore | `operator-service.test.ts` exported a checksummed SQLite backup, ran restore preflight, and proved redacted diagnostics. `database-backup.test.ts` restored into a disposable database, verified committed data and `PRAGMA integrity_check=ok`, rejected tampering, and migrated a representative old schema. These ran in every 10x TS soak iteration. | PASS | No replacement of a running/live controller database (correctly prohibited by design). |
| Diagnostics redaction | Operator fixture inserted a secret endpoint and proved the diagnostics DTO contains only the bounded public fields and not the secret. Agent invalid-start logs on both native hosts did not disclose the supplied canary. | PASS | Service-manager logs were not generated because no service was installed. |
| UI production build | Vite production build passed: 39 modules; generated `dist/index.html`, CSS, JS, and source map. | PASS | No headed browser or screen-reader session. |
| UI accessibility and deep links | 39/39 web/static tests passed, including labelled credentials and fleet/model/operation hash round trips. Static checks confirmed `lang="en"`, title, labelled primary navigation, polite live regions, and alert roles. Controller static-handler tests proved SPA deep-link fallback and security headers. | PASS (static) | No automated axe/WCAG contrast audit and no keyboard/screen-reader manual qualification. |
| Flake soak | Eight high-risk TS files ran 10 iterations: 43 tests/iteration, 430/430 total, including real cross-language enrollment, fleet, artifact install/transfer, backup, operator, chat, and lifecycle paths. | PASS | Physical-host/network flake behavior not exercised. |
| Go race and repeat | Full `go test -race -count=1 ./...` passed. Focused enrollment/fleet/transport/command packages were repeated 10x after repair. The timeout regression test additionally passed 50x and enrollment race tests passed. | PASS after repair | None within fixture scope. |
| Release audit / lock / license / secret scan | `lock-integrity:ok:74`, `license-inventory:ok:78`, `secret-scan:clean`, supply-chain 25/25, and `release-readiness:ok`. | PASS | Audit recognizes unsigned-signing gate; it is not release signing. |
| SBOM / provenance / checksums | Repaired fixture generation produced CycloneDX SBOM with 84 components, six unsigned host-agent provenance statements bound to base commit/digests, package inventory, and seven archive checksums; all archive checksums verified. | PASS as unsigned fixture | Provenance explicitly says unsigned. Controller archive has checksum/inventory evidence but the provenance generator currently emits the six host-agent target statements. |
| Signing/publication | Signing check fails closed by design; no publication or hosted workflow was attempted. | BLOCKED | **Release signing is not configured.** Unsigned packages must not be shipped as a release. |

## Defects found and repaired

All changes below were independently reviewed and committed at `3e131b115c336aea60ab969044f8732823cd6e37`.

1. **Host agent had no bounded CLI help/version path.**
   - Symptom: an operator invoking `--help` would start the long-running service rather than receive help.
   - Repair: added `--help`, `-h`, and `--version`; unknown arguments exit with the existing configuration-rejection code and a redacted message.
   - Evidence: focused Go unit test; native Windows qualification host amd64 package returned usage and `lan-model-agent 0.0.0`.

2. **Polling timeout race produced the wrong terminal status.**
   - Symptom: 10x Go soak intermittently failed `TestPollingEnrollerTimeoutClearsInMemoryPendingMaterial`; when ticker and deadline became ready together, `Complete` could map the expired context to `degraded` rather than bounded `pending` timeout.
   - Repair: after a failed completion, check the polling deadline, discard ephemeral pending proof material, and return `StatusPending`/`ErrUnavailable`.
   - Evidence: regression test 50x; enrollment race suite; focused packages 10x; full Go race and project gate.

3. **Installer tests were not natively portable to Windows.**
   - Symptom: Windows qualification host initially passed 7/9; one assertion hard-coded `/` path separators and a symlink fixture required unavailable Windows symlink privilege.
   - Repair: accept native separators and use a Windows directory junction for the ancestor-redirection fixture.
   - Evidence: Windows qualification host rerun 9/9; Linux supply-chain installer tests 9/9 inside the 25/25 gate.

## Exact command/result summary

- Clean base: `npm ci --ignore-scripts` → 27 packages, 0 vulnerabilities.
- Clean base: `make check` → build pass; TS 589/589; Go all packages pass; supply-chain 25/25; `release-readiness:ok`.
- Reproducibility: two `node scripts/packaging/build.js artifacts/alpha-repro` runs → `built 7 unsigned package(s)` each; complete output hash diff empty; seven archive checksums OK.
- Linux fixture: installer dry-run reported `changed:false`; install `changed:true`; native smoke timeout rc 124; rejected configuration rc 2; uninstall preserved state.
- Windows qualification parser: `WINDOWS_PS_PARSE_OK tokens=651` under Windows PowerShell 5.1.
- Windows qualification installer: first 7/9 exposed portability gaps; repaired rerun 9/9.
- Windows qualification rootless package: dry-run/install/uninstall succeeded; `PERSIST_ME` remained after uninstall.
- TS soak: 10 × 43 = 430 passes, zero failures.
- Go repaired timeout: 50 repeats pass; full race suite pass; focused 10x repeat pass.
- UI/static: Vite build pass; 39/39 tests pass; static accessibility/deep-link checks pass.
- Repaired fixture release artifacts: `provenance:ok:6:unsigned`; `sbom:ok:84`; seven checksums OK; secret scan clean.
- Clean candidate `3e131b1`: two independent package builds produced nine matching output hashes; all seven archive checksums passed.
- Post-repair full gate: `make check` pass; `release-readiness:ok`.

## Named skips and blockers

1. **PowerShell 7.2 service script `-WhatIf`: BLOCKED.** The Windows qualification host lacks `pwsh`; Windows PowerShell 5.1 cannot satisfy the script's declared runtime. Static/native parser evidence is not represented as pwsh execution evidence.
2. **Live service install/start/stop/SCM/ACL validation: SKIPPED BY SAFETY.** The qualification explicitly prohibited enabling or installing real services and any host/firewall mutation. No suitable isolated Windows VM/service sandbox was available.
3. **Native Linux system package/service smoke: SKIPPED BY SAFETY.** Rootless extraction/installer/binary evidence was used; no systemd/sysusers/tmpfiles invocation occurred.
4. **Physical two-host production flow: NOT RUN.** The requirement allowed two-host **or two-process** evidence. Real TS/Go processes over loopback mTLS fulfilled the safe branch. This does not prove physical LAN outage/reconnect, Windows service behavior, or large-model transfer.
5. **Real local Ollama lifecycle/chat mutation: SKIPPED.** The Windows qualification host has an unrelated local Ollama installation, but qualification used fake loopback providers to avoid loading/unloading models or altering unrelated runtime state.
6. **Dynamic accessibility audit: NOT AVAILABLE.** Production/static/deep-link tests passed, but no axe, browser keyboard, screen reader, or formal WCAG contrast run was available.
7. **Signing/publication/hosted workflows: BLOCKED/OUT OF SCOPE.** Signing remains intentionally closed; hosted workflows were not touched; the reviewed qualification repairs were committed and pushed, but no artifact publication or deployment occurred.

## Residual risks

- Windows PowerShell 7.2 runtime behavior, `-WhatIf`, SCM queries, ACL application, virtual-account service execution, health activation, and rollback of a real SCM binary path remain unqualified.
- Physical LAN behavior (sleep/resume, link loss, address change, latency, reconnect, and multi-host clock skew) remains unqualified.
- Real provider lifecycle, streaming backpressure, cancellation, and large peer transfer on the Windows qualification host remain fixture-backed rather than native-provider-backed.
- UI accessibility has strong semantic/static evidence but lacks dynamic assistive-technology evidence.
- The candidate source is committed and reproducibly packaged, but every generated artifact remains explicitly unsigned.

## Ship decision

**NO-SHIP.** Do not publish or install this Alpha as a production release. The code is suitable for continued Alpha review at committed candidate `3e131b1`. The accepted repairs and clean-source reproducibility condition are closed. Remaining minimum closure conditions are: provide PowerShell 7.2 on the Windows qualification host and pass native parse plus `-WhatIf`; add release signing; and either explicitly accept the documented fixture-only residual risks or complete native service/provider/two-host qualification in an isolated sandbox.
