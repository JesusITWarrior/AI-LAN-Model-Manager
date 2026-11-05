#!/usr/bin/env python3
"""Linux-only offline qualification against an explicitly accepted immutable commit."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import tarfile
import tempfile

FIXTURE_SHA256 = "b1645dff696cb22941944a759947893e89a6c69bdacc5705e86907556090b474"
OLD = b"""func writeReplayStore(path string, raw []byte) (bool, error) {
\treturn writeReplayStoreWithFinish(path, raw, finishReplayPublication)
}"""
NEW = b"""func writeReplayStore(path string, raw []byte) (bool, error) {
\treturn writeReplayStoreWithFinish(path, raw, func(string) error { return ErrReplayPersistence })
}"""


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def run(args, cwd, env=None, log=None, timeout=30):
    # Own the process group so a timeout cannot leave a compiler/test child behind.
    with tempfile.TemporaryFile() as output:
        proc = subprocess.Popen(args, cwd=cwd, env=env, stdout=output,
                                stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = proc.wait(timeout=timeout)
        except BaseException:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            output.seek(0)
            if log:
                log.write_bytes(output.read())
            raise
        output.seek(0)
        raw = output.read()
    if log:
        log.write_bytes(raw)
    if code:
        raise RuntimeError(f"exit {code}: {shlex.join(args)}; {raw[-2000:]!r}")
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True, help="exact full accepted commit hash (not a ref)")
    args = parser.parse_args()
    if sys.platform != "linux":
        raise RuntimeError("Linux host only; no Windows execution")
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        raise RuntimeError("--commit must be the full lowercase 40-hex accepted commit")
    script = Path(__file__).resolve()
    repo = script.parents[2]
    actual = run(["git", "rev-parse", "--show-toplevel"], repo).decode().strip()
    if Path(actual).resolve() != repo:
        raise RuntimeError("driver is not in the repository root layout")
    commit = run(["git", "rev-parse", "--verify", args.commit + "^{commit}"], repo).decode().strip()
    if commit != args.commit:
        raise RuntimeError("commit did not resolve exactly")
    tree = run(["git", "rev-parse", commit + "^{tree}"], repo).decode().strip()
    fixture_path = script.parent / "testdata/postpublication-handoff.go.txt"
    fixture = fixture_path.read_bytes()
    if digest(fixture) != FIXTURE_SHA256:
        raise RuntimeError("fixture differs from the exact proven bytes")
    base = repo / "config/private/continuation"
    run(["git", "check-ignore", "--quiet", str(base / "native-overlay-driver-probe")], repo)
    base.mkdir(parents=True, exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix="native-overlay-driver-", dir=base))
    os.chmod(out, 0o700)
    print(f"Artifact directory: {out}", flush=True)
    try:
        (out / "source.commit").write_text(commit + "\n")
        (out / "source.tree").write_text(tree + "\n")
        (out / "checkout-status.txt").write_bytes(run(["git", "status", "--porcelain=v1"], repo))
        # Whole immutable tree, never checkout files (dirty checkout is deliberately allowed).
        archive = out / "source.tar"
        run(["git", "archive", "--format=tar", "--output=" + str(archive), commit], repo)
        source = out / "source"
        source.mkdir()
        with tarfile.open(archive) as tar:
            tar.extractall(source, filter="data")
        originals = {str(p.relative_to(source)): digest(p.read_bytes())
                     for p in sorted(source.rglob("*")) if p.is_file()}
        module = source / "agents/host-agent"
        writer = module / "internal/command/replay_persistence.go"
        lifetime = module / "internal/fleet/command_runner_lifetime_test.go"
        writer_raw, lifetime_raw = writer.read_bytes(), lifetime.read_bytes()
        if writer_raw.count(OLD) != 1:
            raise RuntimeError("writer requires exactly one canonical replacement span")
        if b"TestCommandRunnerSignedPostpublicationFinishFailureHandoff" in lifetime_raw:
            raise RuntimeError("fixture already present in accepted source")
        overlay = out / "overlay"
        overlay.mkdir()
        replacement = overlay / writer.name
        appended = overlay / lifetime.name
        replacement.write_bytes(writer_raw.replace(OLD, NEW, 1))
        appended.write_bytes(lifetime_raw + fixture)
        (overlay / "fixture.txt").write_bytes(fixture)
        if replacement.read_bytes() != writer_raw.replace(OLD, NEW, 1) or appended.read_bytes() != lifetime_raw + fixture:
            raise RuntimeError("overlay byte transformation mismatch")
        mapping = out / "overlay.json"
        mapping.write_text(json.dumps({"Replace": {str(writer): str(replacement), str(lifetime): str(appended)}}, indent=2) + "\n")
        (out / "recipe.json").write_text(json.dumps({
            "source_commit": commit, "source_tree": tree,
            "archive_sha256": digest(archive.read_bytes()),
            "driver_sha256": digest(script.read_bytes()), "fixture_sha256": digest(fixture),
            "inputs": {str(writer.relative_to(source)): digest(writer_raw), str(lifetime.relative_to(source)): digest(lifetime_raw)},
            "old_span": OLD.decode(), "new_span": NEW.decode(),
            "append": "exact original lifetime bytes + exact fixture bytes",
        }, indent=2) + "\n")
        (out / "source-files.json").write_text(json.dumps(originals, indent=2) + "\n")
        env = os.environ.copy()
        env.update(GOENV="off", GOWORK="off", GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local", GOFLAGS="", GOOS="linux")
        commands = [
            (["go", "test", "-overlay", str(mapping), "-race", "-count=3", "./internal/fleet", "-run", "^TestCommandRunnerSignedPostpublicationFinishFailureHandoff$", "-timeout=90s"], "overlay-test.log", 100),
            (["go", "test", "-race", "-count=3", "./internal/command", "./internal/fleet", "./cmd/lan-model-agent"], "unmodified-race.log", 120),
            (["go", "vet", "./..."], "unmodified-vet.log", 60),
        ]
        (out / "test-environment.json").write_text(json.dumps({key: env.get(key) for key in ["GOENV", "GOWORK", "GOPROXY", "GOSUMDB", "GOTOOLCHAIN", "GOFLAGS", "GOOS"]}, indent=2) + "\n")
        run(["go", "version"], module, env, out / "go-version.log")
        run(["go", "env", "GOOS", "GOARCH", "CGO_ENABLED", "GOTOOLCHAIN", "GOWORK", "GOPROXY", "GOSUMDB", "GOFLAGS"], module, env, out / "go-environment.log")
        (out / "commands.txt").write_text("\n".join(shlex.join(cmd) + f" # outer timeout={bound}s" for cmd, _, bound in commands) + "\n")
        for cmd, name, bound in commands:
            run(cmd, module, env, out / name, bound)
            with (out / "status.txt").open("a") as status:
                status.write(name + " PASS\n")
        final = {str(p.relative_to(source)): digest(p.read_bytes())
                 for p in sorted(source.rglob("*")) if p.is_file()}
        if final != originals:
            raise RuntimeError("archived source changed during tests")
        (out / "source-verification.txt").write_text("All archived regular-file hashes unchanged.\n")
        (out / "result.txt").write_text("PASS: overlay race/count=3; unmodified focused race/count=3; vet.\n")
    except BaseException as error:
        (out / "result.txt").write_text(f"FAIL: {type(error).__name__}: {error}\n")
        raise
    finally:
        hashes = {str(p.relative_to(out)): digest(p.read_bytes())
                  for p in sorted(out.rglob("*")) if p.is_file() and not p.is_relative_to(out / "source") and p.name != "generated-artifacts.json"}
        (out / "generated-artifacts.json").write_text(json.dumps(hashes, indent=2) + "\n")
    print("PASS (bounded offline evidence only)", flush=True)


if __name__ == "__main__":
    main()
