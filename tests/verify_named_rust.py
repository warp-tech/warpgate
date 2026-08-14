"""A/B each guard whose discriminator is a Rust unit test.

Split out from `mutation_matrix.py` deliberately. The matrix runs the whole
integration suite for every mutation, because its question is "which tests
notice" — and two full runs of that ended on the canary with unrelated failures
that passed again in isolation, which is W-25b: the suite is not stable under
the load the sweep itself creates.

Under the criterion in §8 the question is narrower once a guard has a named
discriminator: does *that* test notice. One test answers it, creates no load,
and gives a decisive A/B — the named test must pass before the mutation and fail
after. A test that was already red cannot be mistaken for a guard being caught,
because the "before" half catches that first.

    poetry run python -m tests.verify_named_rust

Every file is restored on any exit path, including a kill.
"""

import atexit
import json
import pathlib
import signal
import subprocess
import sys
import time

from .mutation_matrix import DISCRIMINATES, MUTATIONS, REPO, RUST_CRATES

IN_FLIGHT: dict[str, str] = {}
LOCK = REPO / "tests" / ".matrix-running"


def restore_everything():
    for path, text in list(IN_FLIGHT.items()):
        pathlib.Path(path).write_text(text)
        IN_FLIGHT.pop(path, None)
    LOCK.unlink(missing_ok=True)


class CouldNotRun(Exception):
    """A named test could not be executed, so no verdict is available for it."""


_INDEX: dict[str, tuple[str, str]] = {}


def build_index():
    """Test name to crate, listed once per crate rather than once per lookup.

    The first version asked cargo per test per crate. With forty-two guards that
    is over a hundred cargo invocations before a single mutation is applied, and
    it was still in that phase after ten minutes with nothing printed. Three
    calls, done up front.
    """
    for crate in RUST_CRATES:
        listed = subprocess.run(
            ["cargo", "test", "-p", crate, "--", "--list"],
            cwd=REPO,
            capture_output=True,
            text=True,
        )
        for line in listed.stdout.splitlines():
            if line.endswith(": test"):
                # The *full* path, not the bare name. `--exact` matches against
                # the whole `module::path::name`, so filtering by the bare name
                # matches nothing at all — and cargo then exits 0 having run no
                # tests, which this script read as "passed". Every guard would
                # have come back "does not discriminate" while nothing was
                # measured. The first run did exactly that, on the first guard.
                path = line.rsplit(":", 1)[0].strip()
                _INDEX.setdefault(path.split("::")[-1], (crate, path))
        print(f"indexed {crate}", flush=True)


def crate_of(test: str) -> str | None:
    found = _INDEX.get(test)
    return found[0] if found else None


def run_test(crate: str, test: str) -> bool:
    """True if the named test passes.

    "Ran and passed", not "did not fail": a filter matching nothing also exits
    zero, so the count of tests actually run has to be part of the answer.
    """
    path = _INDEX[test][1]
    result = subprocess.run(
        ["cargo", "test", "-p", crate, "--", "--exact", path],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    if "running 1 test" not in result.stdout:
        # Refusing to answer, rather than answering wrongly. Raised per guard
        # and caught by the caller: aborting the whole sweep here cost the
        # thirteen guards after it on a run where the first nine had all come
        # back clean, and the cause turned out to be transient. A verdict this
        # script cannot reach is one guard's worth of missing information, not a
        # reason to discard the rest.
        raise CouldNotRun(
            f"filter {path!r} matched "
            f"{'nothing' if 'running 0 tests' in result.stdout else 'the wrong set'}"
        )
    return result.returncode == 0 and " 0 failed" in result.stdout


def main():
    LOCK.write_text("verify_named_rust is rewriting source files in place\n")
    atexit.register(restore_everything)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: sys.exit(130))

    build_index()
    results = []
    for name, path, old, new in MUTATIONS:
        expected = DISCRIMINATES.get(name, [])
        if not expected:
            continue
        crates = {t: crate_of(t) for t in expected}
        if any(c is None for c in crates.values()):
            continue  # not a Rust discriminator; the integration suite owns it

        try:
            before = {t: run_test(c, t) for t, c in crates.items()}
        except CouldNotRun as why:
            results.append({"guard": name, "status": "could not run", "why": str(why)})
            print(f"{'could not run':>22}  {name}", flush=True)
            continue
        if not all(before.values()):
            results.append({
                "guard": name,
                "status": "already failing",
                "detail": {t: ok for t, ok in before.items()},
            })
            print(f"{'already failing':>22}  {name}", flush=True)
            continue

        source = REPO / path
        original = source.read_text()
        IN_FLIGHT[str(source)] = original
        source.write_text(original.replace(old, new, 1))
        try:
            try:
                after = {t: run_test(c, t) for t, c in crates.items()}
            except CouldNotRun as why:
                results.append({"guard": name, "status": "could not run", "why": str(why)})
                print(f"{'could not run':>22}  {name}", flush=True)
                continue
            # Every named test must notice, per amendment A2.
            status = (
                "discriminates" if not any(after.values()) else "does not discriminate"
            )
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

    good = [r for r in results if r["status"] == "discriminates"]
    (REPO / "tests" / "verify-named-rust.json").write_text(
        json.dumps(
            {
                "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "head": subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=REPO,
                    capture_output=True,
                    text=True,
                ).stdout.strip(),
                "checked": len(results),
                "discriminating": len(good),
                "results": results,
            },
            indent=2,
        )
    )
    print(f"\n{len(good)}/{len(results)} Rust-pinned guards discriminate")
    raise SystemExit(0 if len(good) == len(results) else 1)


if __name__ == "__main__":
    main()
