# Public Alpha support and qualification matrix

**Status:** PRE-RELEASE · **NO-SHIP.** This document is a public status matrix,
not a support announcement. No platform listed here is production-supported,
installation-recommended, or publication-ready. Do **not** publish, install, or
rely on any build described below as a production release.

This matrix intentionally separates two things that are easy to confuse:

- **Source-stage review** — what the source tree builds and what source/build and
  release-gate test suites report (see below). This is **not** package, native,
  lifecycle, signing, or macOS qualification.
- **Release support / qualification** — what still has to run and pass at the
  current commit (or a later release candidate) before any platform could
  plausibly be discussed as supported. See the exact release-closure gates under
  **Current release gates (retain all)**.

The exact-same-commit Alpha qualification that these gates summarize is documented
in [docs/operations/alpha-qualification-report.md](alpha-qualification-report.md).
The deterministic, unsigned Linux/Windows packaging and installation/upgrade
foundations these platforms build on are documented in
[docs/operations/installation-and-upgrades.md](installation-and-upgrades.md).

---

## Platform overview

| Platform | Source target | Packaging / fixture evidence | Native qualification | Current Alpha eligibility | Production / ship support |
| --- | --- | --- | --- | --- | --- |
| **Linux** | Source builds. | Unsigned packaging; historical rootless + fixture install/upgrade evidence. | Exact-current-commit packaged native Alpha gates remain **open**. systemd/service qualification **not** claimed. | Source/fixture-stage Alpha review only. | **NO-SHIP.** Not production-supported; not publication-ready. |
| **Windows** | Host-agent source builds. | Unsigned packaging; fixture, cross-language, and historical bounded native evidence. | Current SCM / service / ACL / reconnect / upgrade Alpha gates remain **open**. | Source/fixture-stage Alpha review only. | **NO-SHIP.** Not production-supported; not publication-ready. |
| **macOS** | Source / cross-build surfaces exist. | Absent. | Native Metal / resource / provider / launchd / package qualification **absent**. | First-Alpha inclusion vs. explicit exclusion is an **owner decision, pending**. | **NO-SHIP.** Not production-supported; not publication-ready. |

The distinction that matters: a platform having a source build and some
fixture/historical evidence is **not** the same as that platform being qualified
or supported. Source-stage review is necessary but far from sufficient; every
platform above remains a review-stage Alpha, and none is shipped.

---

## Linux

- **Source target:** source tree builds.
- **Packaging / fixture evidence:** unsigned package foundations plus historical
  rootless and fixture install/upgrade evidence (source-only — not current native
  qualification).
- **Native qualification:** exact-current-commit packaged **Alpha 1 and Alpha 2
  native gates remain open**. No systemd / `systemctl --user` service
  qualification is claimed.
- **Current Alpha eligibility:** source/fixture-stage Alpha review only.
- **Production / ship support:** **NO-SHIP** — not production-supported, not
  publication-ready.

Current-commit packaged native gates are open; do not read Linux as qualified.

---

## Windows

- **Source target:** host-agent source builds.
- **Packaging / fixture evidence:** unsigned packaging plus fixture, cross-
  language, and historical bounded native evidence (source-only — not current
  native qualification).
- **Native qualification:** current **SCM / service / ACL / reconnect / upgrade
  Alpha gates remain open**.
- **Current Alpha eligibility:** source/fixture-stage Alpha review only.
- **Production / ship support:** **NO-SHIP** — not production-supported, not
  publication-ready.

Current Windows SCM/service/ACL/reconnect/upgrade gates are open; do not read
Windows as qualified or supported.

---

## macOS

- **Source target:** source / cross-build surfaces exist.
- **Packaging / fixture evidence:** absent.
- **Native qualification:** native Metal / resource / provider / launchd /
  package qualification is **absent**.
- **Current Alpha eligibility:** macOS is included in the first Alpha only after native qualification, or explicitly excluded from the first Alpha by owner decision. This document does not decide that outcome.
- **Production / ship support:** **NO-SHIP** — not production-supported, not
  publication-ready.

macOS qualification is absent; inclusion in the first Alpha requires native qualification, and explicit exclusion from the first Alpha is a separate owner decision. Neither outcome is asserted here.

---

## Current release gates (retain all)

Release closure at the current source line (or any later release candidate)
retains **every** minimum condition below. None is closed by this document; each
requires evidence generated at the eventual release candidate, restated exactly
from the current qualification report:

1. **Exact-same-commit packaged Alpha 1 and Alpha 2 native gates.** Reproducible
   clean-source double-build at the exact same commit; Alpha 1 and Alpha 2
   native packages built and passed at that commit (`Hat Trick`/`JarJar`).
2. **Current Windows SCM / service / ACL / reconnect / upgrade evidence.** Live
   Windows SCM query, ACL application, service health activation, reconnect, and
   clean-install/upgrade evidence at the current commit.
3. **Clean-install / upgrade / recovery evidence.** Fresh-install, in-place
   upgrade, and recovery paths qualified at the current commit.
4. **macOS native qualification, or explicit first-Alpha exclusion.** macOS
   native package qualification, **or** an explicit, documented first-Alpha
   exclusion on the macOS track.
5. **Deterministic unsigned RC / SBOM / checksums / provenance rerun.**
   Deterministic unsigned release-candidate package, CycloneDX SBOM, archive
   checksums, and provenance rerun at the eventual candidate.
6. **Approved signing process and material.** An approved signing process and
   signing material in place; signing / publication remain separately authorized.
7. **Documentation and support matrix.** Current documentation and
   support/release matrix.
8. **Explicit owner go/no-go.** A documented owner go/no-go before any
   publication or deployment.

---

## Verdict

- **Source-stage review:** suitable for continued bounded Alpha review — source
  build, source/build, and release-gate test evidence only.
- **Ship / release:** **NO-SHIP.** Do not publish or install any platform as a
  production release.

Every platform above remains a review-stage Alpha with open current-commit native
gates (Linux/Windows) or absent native qualification (macOS), and none is
production-supported or publication-ready.
