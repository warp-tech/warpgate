"""A/B each guard whose discriminator is an integration test.

The companion to `verify_named_rust.py`, and an experiment before it is a tool.

Those nineteen guards were written off as blocked behind W-25b — the suite's
instability under sustained load, which ended two full matrix runs on the canary
with unrelated failures that all passed again in isolation. That write-off was
never measured. W-25b is about the load of running the *whole* suite once per
mutation; this runs one named test, which is the isolation those failures passed
in. If the belief holds, guards will come back "already failing" and the
instability will finally be evidence rather than an assumption. If it does not,
nineteen guards become measurable and the ledger's largest unmeasured claim
closes.

Either outcome is a result. That is the point of running it.

    poetry run python -m tests.verify_named_python           # every such guard
    poetry run python -m tests.verify_named_python <substr>  # ones matching

Every file is restored on any exit path, including a kill.
"""

import atexit
import json
import pathlib
import re
import signal
import subprocess
import sys
import time

from .mutation_matrix import DISCRIMINATES, MUTATIONS, REPO, SUITES

IN_FLIGHT: dict[str, str] = {}
LOCK = REPO / "tests" / ".matrix-running"


def restore_everything():
    for path, text in list(IN_FLIGHT.items()):
        pathlib.Path(path).write_text(text)
        IN_FLIGHT.pop(path, None)
    LOCK.unlink(missing_ok=True)


class CouldNotRun(Exception):
    """The named test did not execute, so there is no verdict to report."""


_COLLECTED: set[str] = set()


def collect():
    """Every integration test name pytest can actually run.

    Collected rather than assumed, for the same reason the Rust half indexes
    before it measures: a name that resolves to nothing cannot fail, and a
    verifier that reads "nothing ran" as "passed" is the defect this project has
    now found three times.
    """
    result = subprocess.run(
        ["poetry", "run", "pytest", *SUITES, "--collect-only", "-q"],
        cwd=REPO / "tests",
        capture_output=True,
        text=True,
    )
    for line in result.stdout.splitlines():
        if "::" in line:
            _COLLECTED.add(line.split("::")[-1].split("[")[0].strip())
    if not _COLLECTED:
        raise SystemExit(
            "pytest collected nothing, so no guard can be measured. Refusing "
            f"rather than reporting verdicts from an empty suite:\n{result.stdout[-400:]}"
        )
    print(f"collected {len(_COLLECTED)} integration tests", flush=True)


def run_test(test: str) -> bool:
    """True if the named test ran and passed.

    "Ran and passed", not "did not fail": pytest exits 5 when its filter matches
    nothing, and a caller reading only the exit code would take that for a pass.
    """
    result = subprocess.run(
        ["poetry", "run", "pytest", *SUITES, "-q", "--tb=no", "-p", "no:randomly", "-k", test],
        cwd=REPO / "tests",
        capture_output=True,
        text=True,
    )
    # Parsed from pytest's own counts rather than matched as substrings. The
    # first version asked whether `" 1 passed"` — with a leading space — was in
    # the output, and pytest's summary line *starts* with the count, so every
    # passing test read as a failure and every guard came back "already
    # failing". That is the W-25b answer this experiment exists to test,
    # manufactured by the instrument measuring it. It survived only because the
    # ruling on this experiment required the failure logs to be read before
    # "already failing" could be believed.
    out = result.stdout
    counts = {
        word: int(number)
        for number, word in re.findall(
            r"(\d+) (passed|failed|error|errors|skipped|deselected)", out
        )
    }
    ran = counts.get("passed", 0) + counts.get("failed", 0) + counts.get("error", 0)
    if ran == 0:
        raise CouldNotRun(f"the filter {test!r} selected no test: {out.strip()[-200:]}")
    if ran != 1:
        raise CouldNotRun(f"the filter {test!r} selected {ran} tests: {out.strip()[-200:]}")
    return counts.get("passed", 0) == 1


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else ""
    LOCK.write_text("verify_named_python is rewriting source files in place\n")
    atexit.register(restore_everything)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: sys.exit(130))

    collect()
    results = []
    for name, path, old, new in MUTATIONS:
        expected = DISCRIMINATES.get(name, [])
        if only and only not in name:
            continue
        # Ours only: a guard whose every discriminator is an integration test.
        if not expected or not all(t in _COLLECTED for t in expected):
            continue

        try:
            before = {t: run_test(t) for t in expected}
        except CouldNotRun as why:
            results.append({"guard": name, "status": "could not run", "why": str(why)})
            print(f"{'could not run':>22}  {name}", flush=True)
            continue
        if not all(before.values()):
            # The W-25b case. Recorded as its own outcome rather than folded into
            # a failure: a test that was already red says nothing about the guard.
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
                # A mutation that does not compile measures nothing — the rule
                # the matrix states in its own header, and the one a broken
                # entry silently violated for three runs.
                results.append({"guard": name, "status": "did not compile"})
                print(f"{'did not compile':>22}  {name}", flush=True)
                continue
            try:
                after = {t: run_test(t) for t in expected}
            except CouldNotRun as why:
                results.append({"guard": name, "status": "could not run", "why": str(why)})
                print(f"{'could not run':>22}  {name}", flush=True)
                continue
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

    subprocess.run(["cargo", "build", "--bin", "warpgate"], cwd=REPO, capture_output=True)
    good = [r for r in results if r["status"] == "discriminates"]
    (REPO / "tests" / "verify-named-python.json").write_text(
        json.dumps(
            {
                "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "head": subprocess.run(
                    ["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True
                ).stdout.strip(),
                "partial": bool(only),
                "checked": len(results),
                "discriminating": len(good),
                "results": results,
            },
            indent=2,
        )
    )
    print(f"\n{len(good)}/{len(results)} integration-pinned guards discriminate")
    raise SystemExit(0 if results and len(good) == len(results) else 1)


if __name__ == "__main__":
    main()
