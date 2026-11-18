import test from"node:test";
import assert from"node:assert/strict";
import{readFileSync,existsSync}from"node:fs";
import{fileURLToPath}from"node:url";
import{resolve}from"node:path";
import{evaluateReleaseAudit,REQUIRED_DOCS,REQUIRED_GATES,REQUIRED_SCRIPT_FILES,REQUIRED_TEST_FILES}from"../audit.js";

const good=()=>({
  dirtyTree:false,
  workflowTexts:["on:\n  workflow_dispatch:\n"],
  presentFiles:[...REQUIRED_DOCS,...REQUIRED_TEST_FILES,...REQUIRED_SCRIPT_FILES],
  publicDocs:["Artifacts are unsigned. Release signing is not operational."],
  gateResults:Object.fromEntries(REQUIRED_GATES.map(k=>[k,true])),
});

test("complete source and gate evidence passes",()=>assert.deepEqual(evaluateReleaseAudit(good()),{ok:true,failures:[]}));

test("release mode rejects dirty source",()=>{
  const result=evaluateReleaseAudit({...good(),dirtyTree:true});
  assert.equal(result.ok,false);
  assert.ok(result.failures.some(f=>f.error==="ERR_DIRTY_TREE"));
  assert.equal(evaluateReleaseAudit({...good(),dirtyTree:true,allowDirty:true}).ok,true);
});

test("automatic or absent workflow triggers fail closed",()=>{
  for(const text of["on:\n  push:\n","on:\n  pull_request:\n","on:\n  schedule:\n","on:\n  workflow_call:\n",""]) {
    assert.ok(evaluateReleaseAudit({...good(),workflowTexts:[text]}).failures.some(f=>f.error==="ERR_WORKFLOW_POLICY"));
  }
});

test("every required document test and script is mandatory",()=>{
  for(const [list,error]of[[REQUIRED_DOCS,"ERR_REQUIRED_DOCUMENT"],[REQUIRED_TEST_FILES,"ERR_REQUIRED_TEST"],[REQUIRED_SCRIPT_FILES,"ERR_REQUIRED_SCRIPT"]]as const){
    const present=good().presentFiles.filter(name=>name!==list[0]);
    assert.ok(evaluateReleaseAudit({...good(),presentFiles:present}).failures.some(f=>f.error===error));
  }
});

test("every underlying release gate must have positive evidence",()=>{
  for(const gate of REQUIRED_GATES){
    const results={...good().gateResults,[gate]:false};
    assert.ok(evaluateReleaseAudit({...good(),gateResults:results}).failures.some(f=>f.error==="ERR_REQUIRED_GATE"));
  }
});

test("public docs cannot claim unsigned artifacts are signed",()=>{
  for(const text of["Release artifacts are signed.","The package is cryptographically signed."]){
    assert.ok(evaluateReleaseAudit({...good(),publicDocs:[text]}).failures.some(f=>f.error==="ERR_UNSIGNED_SIGNING_CLAIM"));
  }
  for(const text of["Artifacts are unsigned.","Release packages are not signed.","Signing is planned but not operational."]){
    assert.equal(evaluateReleaseAudit({...good(),publicDocs:[text]}).ok,true);
  }
});

// ---- Owner-evidence documentation regression ----

const DOC_BASE=resolve(fileURLToPath(import.meta.url),"..","..","..","..");
function doc(name:string):string{return readFileSync(resolve(DOC_BASE,name),"utf8");}
const operatorDoc=doc("docs/operations/operator-console.md");
const architectureDoc=doc("docs/architecture.md");
const threatDoc=doc("docs/threat-model.md");

function mustContain(what:string[],hay:string[],label:string):void{
  for(const marker of what){
    assert.ok(hay.some(text=>text.includes(marker)),`${label}: expected content missing: "${marker}"`);
  }
}
function mustNotContain(what:string[],hay:string[],label:string):void{
  for(const forbidden of what){
    assert.ok(!hay.some(text=>text.includes(forbidden)),`${label}: unexpected misleading content present: "${forbidden}"`);
  }
}

test("operator-console documents the owner-evidence workflow",()=>{
  mustContain([
    "Owner-provided unsigned evidence; source not independently proven",
    "separate explicit",
    "stored",
    "already_stored",
    "conflict",
    "stale",
    "denied",
    "transaction_unknown",
    "committed_unsettled",
    "fresh explicit re-intake",
    "never executes or retries",
    "ACKs a command",
    "releases a hold",
  ],[operatorDoc],"operator-console.md");
  // Defect 1 correction: persisted `stored` writes one append-only row to
  // supplemental_native_evidence plus a matching supplemental_native_evidence_audit
  // event, and leaves jobs/history/commands/replay/holds unchanged.
  mustContain(
    ["persists one append-only row to `supplemental_native_evidence`",
     "does **not** modify jobs, history, commands, replay, or holds"],
    [operatorDoc],
    "operator-console.md stored semantics"
  );
  // Defect 1 negative: `stored` is never described as a read-only append.
  mustNotContain(
    ["read-only append"],
    [operatorDoc],
    "operator-console.md must not call stored a read-only append"
  );
});

test("architecture documents the owner-evidence lane boundaries",()=>{
  mustContain([
    "Owner-provided unsigned evidence",
    "volatile owner/session/credential-bound candidate registry",
    "same-transaction",
    "append-only row",
    "queue remains authoritative input and is left unchanged",
    "audit event",
    "native ACK",
    "hold release",
  ],[architectureDoc],"architecture.md");
  // Defect 2 negative: the transaction must not be described as appending only the
  // stored queue; the queue is authoritative input and stays unchanged.
  mustNotContain(
    ["append-only of the stored queue", "append-only of the queue"],
    [architectureDoc],
    "architecture.md must not claim append-only of the stored queue"
  );
});

test("threat model documents owner evidence as untrusted ingress",()=>{
  mustContain([
    "Owner evidence bytes are untrusted ingress",
    "strict UTF-8/JSON/duplicate-key/shape/cap",
    "same-origin session",
    "append-only",
    "audit commit",
    "may be false or benign",
    "remote possession",
    "fresh mTLS",
    "does **not** attest",
  ],[threatDoc],"threat-model.md");
  // Defect 3 negative: prepare must not claim the lane attests provenance/truthfulness.
  mustNotContain(
    ["attests provenance at prepare time"],
    [threatDoc],
    "threat-model.md must not claim the lane attests provenance at prepare time"
  );
});

test("operator console does not strand a newline before the prepare sentence", () => {
  // Stray newline-period form must NOT be present: `**Prepare**` must be followed
  // on the same paragraph by `. Preparation`, never split across two paragraphs.
  mustNotContain(["**Prepare**\n. Preparation"], [operatorConsoleDoc],
    "operator-console.md must not contain a newline before the prepare sentence");
});

// ---- Alpha-qualification report regression ----

const alphaDocName = "docs/operations/alpha-qualification-report.md";
const alphaDoc = doc(alphaDocName);

// The historical snapshot contains truthful negated markers: they describe only what
// executed at the September checkpoint, never at the current HEAD. Only positive
// current-execution claims are rejected — the honest "not" markers are required.
test("alpha-qualification report is a current-status, non-unit report", () => {
  // Requirement 1: non-unit title (no Phase-18.13 unit heading).
  mustNotContain(["Phase 18.13"], [alphaDoc], "alpha-qualification report");
  mustContain(["Phase 18 Alpha qualification report"], [alphaDoc], "alpha-qualification report title");

  // Requirement 2: preserved historical snapshot clearly separated from current work.
  mustContain(["Historical qualification snapshot"], [alphaDoc], "alpha-qualification report");
  // Truthful negated historical markers REQUIRE present; these describe what executed
  // at the September checkpoint, never at the current HEAD.
  mustContain(
    ["was **not** rerun at later commits", "did not execute at `f7e40ae3a365459ddf0dc5264a3f1155b34b2a5c`"],
    [alphaDoc],
    "alpha-qualification report historical separation",
  );
  // Only positive current-execution claims are rejected (never the honest "not" markers).
  mustNotContain(
    ["was rerun", "rebuilt at f7e40ae3a365459ddf0dc5264a3f1155b34b2a5c"],
    [alphaDoc],
    "alpha-qualification report positive-execution claims",
  );

  // Requirement 3: current accepted source checkpoint named exactly (f7e40ae3a365459ddf0dc5264a3f1155b34b2a5c).
  mustContain(
    ["f7e40ae3a365459ddf0dc5264a3f1155b34b2a5c"],
    [alphaDoc],
    "alpha-qualification report",
  );
  mustContain(["Current accepted source checkpoint"], [alphaDoc], "alpha-qualification report");

  // Requirement 3b: current checkpoint evidence numbers (source only, not package/native qualification).
  // Focused owner-documentation regression 14/14; supply-chain 38 pass / 0 fail / 1 intentional Windows native-fixture skip; Fedora 10/10; full suite 1060/1060.
  mustContain(["14/14"], [alphaDoc], "alpha-qualification report focused audit");
  mustContain(["38 (pass)"], [alphaDoc], "alpha-qualification report supply-chain");
  mustContain(["0 fail"], [alphaDoc], "alpha-qualification report supply-chain");
  mustContain(["intentional Windows native-fixture skip"], [alphaDoc], "alpha-qualification report");
  mustContain(["Fedora 10/10"], [alphaDoc], "alpha-qualification report");
  mustContain(["1060/1060"], [alphaDoc], "alpha-qualification report");
  // The report must link the current related documents.
  mustContain(["operator-console.md"], [alphaDoc], "alpha-qualification report operator-console link");
  mustContain(["[alpha-support-matrix.md](alpha-support-matrix.md)"], [alphaDoc], "alpha-qualification report support-matrix link");
  mustNotContain(
    ["[alpha-support-matrix.md](alpha-qualification-report.md)"],
    [alphaDoc],
    "alpha-qualification report must not self-link as the support matrix",
  );
  // Reject affirmative current package/native/signing/publication claims; NO-SHIP must remain.
  mustNotContain(
    ["is production-ready", "native service qualification performed", "signed as a release"],
    [alphaDoc],
    "alpha-qualification report must not affirmatively claim native/package/signing/publication",
  );
  // Stale current-checkpoint reference (e6695cb) must be rejected.
  mustNotContain(
    ["e6695cb0cfefea24269add6401f95490017d1200", "at e6695cb"],
    [alphaDoc],
    "alpha-qualification report must not reference stale e6695cb current checkpoint",
  );

  // Requirement 4: explicit source-vs-ship verdict split.
  mustContain(["Source test-stage"], [alphaDoc], "alpha-qualification report verdict");
  mustContain(["Ship/release"], [alphaDoc], "alpha-qualification report verdict");

  // Requirement 5: NO-SHIP for ship/release.
  mustContain(["NO-SHIP"], [alphaDoc], "alpha-qualification report NO-SHIP");

  // Requirement 6: the current checkpoint is described as source only — not package or native qualification.
  mustContain(["**not** package or native qualification"], [alphaDoc], "alpha-qualification report source-only");

  // Requirement 7: current release-closure gates enumerated (retain all).
  mustContain(
    ["Current release-closure conditions (retain all)"],
    [alphaDoc],
    "alpha-qualification report",
  );
  mustContain(["Exact-same-commit packaged Alpha 1 and Alpha 2 native gates"], [alphaDoc], "alpha-qualification report");
  mustContain(["macOS native qualification, or explicit first-Alpha exclusion"], [alphaDoc], "alpha-qualification report");
  mustContain(["Deterministic unsigned RC / SBOM / checksums / provenance rerun"], [alphaDoc], "alpha-qualification report");

  // Requirement 8: the honest residual states these were NOT performed at e6695cb
  // (negated on the report). Assert the negated residual is present, and never assert
  // any positive current double-build / native-service / two-host drill claim.
  mustContain(
    ["no clean reproducible package double-build", "no native service qualification", "no two-host lifecycle/inference/transfer drill"],
    [alphaDoc],
    "alpha-qualification report no-current-execution residual",
  );

  // Stale (historical/closed) sentences must be rejected.
  mustNotContain(
    ["continued Alpha review is at `3e131b1`", "provide PowerShell 7.2 on the Windows qualification host"],
    [alphaDoc],
    "stale current-review and closure sentences",
  );
});

// ---- Public Alpha support matrix regression ----

const matrixDocName = "docs/operations/alpha-support-matrix.md";
const matrixDoc = doc(matrixDocName);

// The public support matrix must not misrepresent platform status. It encodes a
// strict source-vs-support split, keeps all three platform boundaries, records the
// macOS owner-decision-pending state, and references the major release gates.
test("public alpha support matrix encodes NO-SHIP and source-vs-support split", () => {
  // NO-SHIP present, and explicit source-vs-support distinction.
  mustContain(["NO-SHIP"], [matrixDoc], "alpha support matrix");
  mustContain(["Source-stage review"], [matrixDoc], "alpha support matrix");

  // All three platform boundaries present.
  mustContain(["**Linux**", "**Windows**", "**macOS**"], [matrixDoc], "alpha support matrix platform boundaries");

  // macOS inclusion/exclusion semantics: corrected wording, not the malformed
  // "enters ... by explicit exclusion" which reverses exclusion meaning.
  mustContain(
    ["included in the first Alpha only after native qualification",
     "explicitly excluded from the first Alpha by owner decision"],
    [matrixDoc],
    "alpha support matrix macOS inclusion/exclusion semantics"
  );

  // Major release gates referenced.
  mustContain(
    ["Exact-same-commit packaged Alpha 1 and Alpha 2 native gates",
     "macOS native qualification, or explicit first-Alpha exclusion",
     "Deterministic unsigned RC / SBOM / checksums / provenance rerun",
     "Current release gates"],
    [matrixDoc],
    "alpha support matrix release gates"
  );

  // The following misleading statuses must NOT be present: all three platforms
  // qualified/supported, macOS qualified, or any platform production-ready.
  // Markers are chosen to fire only on *affirmative* claims (never on correct
  // "not X"/"NO-SHIP" negations), matching the matrix as written.
  mustNotContain(
    [
      "are all three platforms",
      "all three platforms are qualified",
      "all three platforms are supported",
      "macOS Alpha support is qualified",
      "macOS is qualified",
      "are all three platforms qualified",
      "is production-ready",
    ],
    [matrixDoc],
    "alpha support matrix must not claim platform qualification/support"
  );

  // The malformed exclusion-reversal phrase must NOT be present.
  mustNotContain(
    [
      "enters the first Alpha by explicit exclusion",
      "by explicit exclusion, or is included",
      "first-Alpha inclusion versus explicit exclusion",
    ],
    [matrixDoc],
    "alpha support matrix must not reverse macOS exclusion semantics"
  );
});

// ---- Public alpha support matrix link resolution regression ----

const matrixDir = resolve(DOC_BASE, "docs", "operations");
// Markdown link hrefs only (text inside [...] is not matched; only href inside (...)).
const matrixLinkRegex = /\]\(([^)^\s]+)\)/g;

test("public alpha support matrix links resolve to existing same-directory docs", () => {
  // b) Extract every markdown link href from the matrix.
  const hrefs = [...matrixDoc.matchAll(matrixLinkRegex)].map(m => m[1]);

  // c) Both documented link targets must appear as hrefs.
  assert.ok(
    hrefs.includes("alpha-qualification-report.md"),
    "matrix must link alpha-qualification-report.md (same directory)"
  );
  assert.ok(
    hrefs.includes("installation-and-upgrades.md"),
    "matrix must link installation-and-upgrades.md (same directory)"
  );

  // The links must not use a broken ../ escape: both targets live in the same
  // directory (docs/operations/), so no parent-directory traversal is allowed.
  assert.ok(
    !hrefs.some(h => h.startsWith("../")),
    "matrix must not use ../ escaped links; targets live in the same directory"
  );

  // d) Resolve each relative to the matrix document's directory and assert it exists.
  for (const target of ["alpha-qualification-report.md", "installation-and-upgrades.md"]) {
    const resolved = resolve(matrixDir, target);
    assert.ok(existsSync(resolved), `${target} resolves to an existing file relative to docs/operations/`);
  }

  // e) Re-verify all prior positive markers after the link correction.
  mustContain(["NO-SHIP"], [matrixDoc], "alpha support matrix");
  mustContain(["Source-stage review"], [matrixDoc], "alpha support matrix");
  mustContain(["**Linux**", "**Windows**", "**macOS**"], [matrixDoc], "alpha support matrix platform boundaries");

  // macOS inclusion/exclusion semantics: corrected wording, not the malformed
  // "enters ... by explicit exclusion" which reverses exclusion meaning.
  mustContain(
    ["included in the first Alpha only after native qualification",
     "explicitly excluded from the first Alpha by owner decision"],
    [matrixDoc],
    "alpha support matrix macOS inclusion/exclusion semantics"
  );
  mustContain(
    ["Exact-same-commit packaged Alpha 1 and Alpha 2 native gates",
     "macOS native qualification, or explicit first-Alpha exclusion",
     "Deterministic unsigned RC / SBOM / checksums / provenance rerun",
     "Current release gates"],
    [matrixDoc],
    "alpha support matrix release gates"
  );

  // f) Re-verify all prior negative markers still reject misleading claims.
  mustNotContain(
    [
      "are all three platforms",
      "all three platforms are qualified",
      "all three platforms are supported",
      "macOS Alpha support is qualified",
      "macOS is qualified",
      "are all three platforms qualified",
      "is production-ready",
    ],
    [matrixDoc],
    "alpha support matrix must not claim platform qualification/support"
  );

  // The malformed exclusion-reversal phrase must NOT be present.
  mustNotContain(
    [
      "enters the first Alpha by explicit exclusion",
      "by explicit exclusion, or is included",
      "first-Alpha inclusion versus explicit exclusion",
    ],
    [matrixDoc],
    "alpha support matrix must not reverse macOS exclusion semantics"
  );
});

// ---- Operator console consumer-journey regression ----

const operatorConsoleDocName = "docs/operations/operator-console.md";
const operatorConsoleDoc = doc(operatorConsoleDocName);

// The operator console must present a truthful consumer journey for an unsigned
// internal Alpha: topology/current status, install+first start linking the
// existing guide, pairing/revoke/re-enroll, loopback inference client config with
// a separate bearer (no management-cookie reuse), backup/restore boundaries,
// bounded troubleshooting linking enrollment-diagnosis.md, and a known-limits /
// NO-SHIP section linking alpha-support-matrix.md. It must NOT claim any platform
// is production-ready or that port 7341 serves inference.
test("operator console presents an honest consumer journey and NO-SHIP limits", () => {
  // Topology / current-status section present.
  mustContain(
    ["Topology / current status"],
    [operatorConsoleDoc],
    "operator console topology/current-status"
  );

  // Install + first start point at the existing guide; nothing invented.
  mustContain(
    ["installation-and-upgrades.md"],
    [operatorConsoleDoc],
    "operator console install-first-start link"
  );

  // Pairing / revoke / re-enroll content preserved.
  mustContain(
    ["Pair and enroll a host", "Rename, revoke, and re-enroll"],
    [operatorConsoleDoc],
    "operator console pairing/revoke/re-enroll"
  );

  // Inference client configured via loopback URL with a separate bearer token.
  mustContain(
    ["http://127.0.0.1:7340/v1"],
    [operatorConsoleDoc],
    "operator console inference-client loopback URL"
  );

  // Backup / restore boundary preserved.
  mustContain(
    ["Backup and restore"],
    [operatorConsoleDoc],
    "operator console backup/restore boundary"
  );

  // Troubleshooting links to enrollment-diagnosis.md.
  mustContain(
    ["enrollment-diagnosis.md"],
    [operatorConsoleDoc],
    "operator console troubleshooting link"
  );

  // Known-limits / NO-SHIP section linking alpha-support-matrix.md.
  mustContain(
    ["Known limits / qualification", "alpha-support-matrix.md"],
    [operatorConsoleDoc],
    "operator console known-limits / alpha-matrix link"
  );

  // Negative / misleading claims must NOT be present (affirmative only, never
  // the honest "not X" / "NO-SHIP" negations).
  mustNotContain(
    [
      "is production-ready",
      "serving inference on port 7341",
      "binds a second listener on port 7341",
      "management cookie",
      "reuse the management",
    ],
    [operatorConsoleDoc],
    "operator console must not claim production-ready / second 7341 listener / management-cookie reuse"
  );
});


// ---- Cross-platform output-path containment regression ----
//
// The production `contained(base, value, api = node:path)` helper (exported from
// build.js) uses a fail-closed descendant test: `value` is contained only when
// `api.resolve(value)` is strictly nested under `api.resolve(base)` using the same
// path API. It takes an explicit `api` parameter (default native `node:path`) so
// the same logic can be proven under both POSIX and Windows path semantics on a
// single Linux runner. The helper is asserted directly here (rather than through
// the full `buildPackages()` build, which invokes the Go toolchain and would
// attempt an out-of-repo `rm`) so these are fast, mutation-free negative tests.
//
// Both `path.posix` and `path.win32` are invoked to prove the fix is
// cross-platform, not merely true on this Linux host.
test("package output path is a strict descendant under posix and win32 semantics",async()=>{const{contained}=await import("../build.js").then(m=>{if(typeof m.contained!="function")throw new Error("contained must be exported from build.js");return m;});const{posix,win32}=await import("node:path");const root=resolve(import.meta.dirname,"../../..");
// Native default (node:path) is fail-closed for a strict child:
assert.equal(contained(root,"artifacts/host-agent"),true);
// posix: strict children accepted; root, parent escape, traversal, sibling-prefix rejected:
assert.equal(contained(root,"artifacts",posix),true);
assert.equal(contained(root,root,posix),false);
assert.equal(contained(root,"..",posix),false);
assert.equal(contained(root,"../outside",posix),false);
assert.equal(contained(root,"../repo/target",posix),false);
assert.equal(contained(posix.resolve(root,"artifacts"),posix.resolve(root,"artifacts-host"),posix),false);
// posix cross-root input is not contained:
assert.equal(contained(root,"/out",posix),false);
// win32: same-drive descendant accepted; parent escape / cross-drive / sibling-prefix rejected:
assert.equal(contained("C:\\\\repo","C:\\\\repo\\\\artifacts\\\\x",win32),true);
assert.equal(contained("C:\\\\repo","C:\\\\..\\\\out",win32),false);
assert.equal(contained("C:\\\\repo","D:\\\\out",win32),false);
assert.equal(contained("C:\\\\repo","C:\\\\repo-evil",win32),false);
});

// buildPackages must reject any output path that is the repo root, escapes it, or is
// only a sibling-prefix — before any Go build or filesystem mutation runs. All three
// values resolve strictly outside the repo root, so each short-circuits with
// ERR_OUTPUT_PATH before any rm()/Go/npm work runs.
test("buildPackages rejects out-of-repo, repo-root, and sibling-prefix output paths before mutation",async()=>{const {buildPackages}=await import("../build.js").then(m=>{if(typeof m.buildPackages!="function")throw new Error("buildPackages must be exported from build.js");return m;});const root=resolve(import.meta.dirname,"../../..");
for (const value of [".","..","../outside","../repo-evil"]) {
  let message = "";
  try { await buildPackages(value); } catch (e) { message = e instanceof Error ? e.message : String(e); }
  assert.equal(message, "ERR_OUTPUT_PATH", `expected buildPackages(${JSON.stringify(value)}) to fail with ERR_OUTPUT_PATH`);
}
});
