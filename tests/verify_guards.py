"""A/B every guard against the test named after it, whatever language it is in.

Supersedes `verify_named_rust.py` and `verify_named_python.py`, which split the
work by the language of the discriminating test. That split had a hole neither
half could see: a guard naming a Rust test *and* an integration test was claimed
by neither, because each required every name to be in its own domain and skipped
otherwise without a word. Four guards sat unmeasured that way, two of them added
by the round that was supposed to be measuring things.

One verifier, dispatching per test, cannot lose a guard between two tools.

The criterion is §8's: the test named after a guard must pass with the guard in
place and fail with it disabled. Anything else is not evidence — the integration
suite runs against a real sshd that refuses most of this independently, so "the
connection failed" says nothing about our code.

    poetry run python -m tests.verify_guards           # every guard
    poetry run python -m tests.verify_guards <substr>  # ones matching

Every file is restored on any exit path, including a kill. The binary is rebuilt
after every restore: the integration suite runs `target/debug/warpgate`, and
restoring a source file does not restore an executable.
"""

import atexit
import json
import pathlib
import re
import signal
import subprocess
import sys
import time

from .mutation_matrix import DISCRIMINATES, MUTATIONS, REPO, RUST_CRATES, SUITES

IN_FLIGHT: dict[str, str] = {}
LOCK = REPO / "tests" / ".matrix-running"


def restore_everything():
    for path, text in list(IN_FLIGHT.items()):
        pathlib.Path(path).write_text(text)
        IN_FLIGHT.pop(path, None)
    LOCK.unlink(missing_ok=True)


class CouldNotRun(Exception):
    """A named test did not execute, so there is no verdict to report."""


# Test name to how it is run: ("rust", crate, full::path) or ("pytest",).
_INDEX: dict[str, tuple] = {}


def build_index():
    """Every test this repository has, and how to run each one.

    Collected, never assumed. A name that resolves to nothing cannot fail, so a
    verifier that reads "nothing ran" as "passed" reports coverage that does not
    exist — the defect this project has now found three times in three different
    instruments.
    """
    for crate in RUST_CRATES:
        listed = subprocess.run(
            ["cargo", "test", "-p", crate, "--", "--list"],
            cwd=REPO, capture_output=True, text=True,
        )
        for line in listed.stdout.splitlines():
            if line.endswith(": test"):
                path = line.rsplit(":", 1)[0].strip()
                _INDEX.setdefault(path.split("::")[-1], ("rust", crate, path))

    collected = subprocess.run(
        ["poetry", "run", "pytest", *SUITES, "--collect-only", "-q"],
        cwd=REPO / "tests", capture_output=True, text=True,
    )
    for line in collected.stdout.splitlines():
        if "::" in line:
            _INDEX.setdefault(line.split("::")[-1].split("[")[0].strip(), ("pytest",))

    print(f"indexed {len(_INDEX)} tests across {len(RUST_CRATES)} crates and the suite", flush=True)


def check_every_discriminator_exists():
    """Refuse before measuring if a named test does not exist.

    Cheap, and it caught a guard credited to a test that had never been written.
    """
    missing = [
        (guard, test)
        for guard, *_ in MUTATIONS
        for test in DISCRIMINATES.get(guard, [])
        if test not in _INDEX
    ]
    if missing:
        lines = "\n".join(f"  {t}\n    named by {g}" for g, t in missing)
        raise SystemExit(f"{len(missing)} named discriminator(s) do not exist:\n{lines}")

    unnamed = [g for g, *_ in MUTATIONS if not DISCRIMINATES.get(g)]
    if unnamed:
        lines = "\n".join(f"  {g}" for g in unnamed)
        raise SystemExit(f"{len(unnamed)} guard(s) name no discriminator:\n{lines}")


def run_test(test: str) -> bool:
    """True if the named test ran and passed. Raises if it did not run.

    "Ran and passed", never "did not fail": a filter that matches nothing exits
    zero in both runners.
    """
    how = _INDEX[test]
    if how[0] == "rust":
        _, crate, path = how
        result = subprocess.run(
            ["cargo", "test", "-p", crate, "--lib", "--", "--exact", path],
            cwd=REPO, capture_output=True, text=True,
        )
        if "running 1 test" not in result.stdout:
            raise CouldNotRun(f"{path!r} selected no test: {result.stdout.strip()[-200:]}")
        return result.returncode == 0 and " 0 failed" in result.stdout

    result = subprocess.run(
        ["poetry", "run", "pytest", *SUITES, "-q", "--tb=no", "-p", "no:randomly", "-k", test],
        cwd=REPO / "tests", capture_output=True, text=True,
    )
    counts = {
        word: int(number)
        for number, word in re.findall(
            r"(\d+) (passed|failed|error|errors|skipped|deselected)", result.stdout
        )
    }
    ran = counts.get("passed", 0) + counts.get("failed", 0) + counts.get("error", 0)
    if ran != 1:
        raise CouldNotRun(f"{test!r} selected {ran} tests: {result.stdout.strip()[-200:]}")
    return counts.get("passed", 0) == 1


def rebuild():
    subprocess.run(["cargo", "build", "--bin", "warpgate"], cwd=REPO, capture_output=True)


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else ""
    LOCK.write_text("verify_guards is rewriting source files in place\n")
    atexit.register(restore_everything)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: sys.exit(130))

    build_index()
    check_every_discriminator_exists()
    rebuild()

    results = []
    for name, path, old, new in MUTATIONS:
        if only and only not in name:
            continue
        expected = DISCRIMINATES[name]

        try:
            before = {t: run_test(t) for t in expected}
        except CouldNotRun as why:
            results.append({"guard": name, "status": "could not run", "why": str(why)})
            print(f"{'could not run':>22}  {name}", flush=True)
            continue
        if not all(before.values()):
            results.append({
                "guard": name,
                "status": "already failing",
                "tests": [t for t, ok in before.items() if not ok],
            })
            print(f"{'already failing':>22}  {name}", flush=True)
            continue

        source = REPO / path
        original = source.read_text()
        IN_FLIGHT[str(source)] = original
        source.write_text(original.replace(old, new, 1))
        try:
            build = subprocess.run(
                ["cargo", "build", "--bin", "warpgate"], cwd=REPO, capture_output=True, text=True
            )
            if build.returncode != 0:
                results.append({"guard": name, "status": "did not compile"})
                print(f"{'did not compile':>22}  {name}", flush=True)
                continue
            try:
                after = {t: run_test(t) for t in expected}
            except CouldNotRun as why:
                results.append({"guard": name, "status": "could not run", "why": str(why)})
                print(f"{'could not run':>22}  {name}", flush=True)
                continue
            # Every named test must notice, per amendment A2. One test noticing
            # for another is how a Rust unit test came to stand as evidence for
            # an integration test that had never been shown to discriminate.
            status = "discriminates" if not any(after.values()) else "does not discriminate"
            results.append({
                "guard": name,
                "status": status,
                "tests": expected,
                "passed_with_guard_off": [t for t, ok in after.items() if ok],
            })
            print(f"{status:>22}  {name}", flush=True)
        finally:
            source.write_text(original)
            IN_FLIGHT.pop(str(source), None)
            rebuild()

    good = [r for r in results if r["status"] == "discriminates"]
    (REPO / "tests" / "verify-guards.json").write_text(
        json.dumps(
            {
                "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "head": subprocess.run(
                    ["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True
                ).stdout.strip(),
                "partial": bool(only),
                "guards_total": len(MUTATIONS),
                "measured": len(results),
                "discriminating": len(good),
                "results": results,
            },
            indent=2,
        )
    )
    print(f"\n{len(good)}/{len(results)} guards discriminate, of {len(MUTATIONS)} defined")
    raise SystemExit(0 if results and len(good) == len(results) else 1)


if __name__ == "__main__":
    main()
