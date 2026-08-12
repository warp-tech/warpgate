"""Turn each guard off in turn and record which test notices.

Written after a reviewer found several tests that passed without exercising what
they were named for. Checking tests one at a time, by hand, is how that happens:
you verify the test you just wrote and never ask which *other* test would have
caught the same thing, or whether any test covers a guard nobody thought to
break.

Two things come out of a run. A guard that no test catches is a hole. A test
that never fails for any mutation is doing less than its name suggests — not
proof that it is useless, but the place to look next.

Not a pytest module: it rebuilds the gateway between runs, so it is a script.

    poetry run python -m tests.mutation_matrix           # every guard
    poetry run python -m tests.mutation_matrix principal # ones matching a name
"""

import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Each mutation names a guard and the edit that disables it. The replacement has
# to compile — a mutation that fails to build proves nothing about the tests.
MUTATIONS = [
    (
        "certificate: key ID must match",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "if certificate.key_id() != key_id {",
        "if false {",
    ),
    (
        "certificate: must be a user certificate",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "if certificate.cert_type() != CertType::User {",
        "if false {",
    ),
    (
        "certificate: must certify our ephemeral key",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "if certificate.public_key() != key.key_data() {",
        "if false {",
    ),
    (
        "certificate: principals must be exactly the target account",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "if principals.len() != 1 || principals.first().is_none_or(|only| only != principal) {",
        "if false {",
    ),
    (
        "certificate: pinned critical options must be present",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "if !certificate.critical_options().contains_key(&expected.name) {",
        "if false {",
    ),
    (
        "certificate: unexpected critical options refused",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "let permitted = allowed_options.iter().find(|option| &option.name == name);",
        "let permitted = Some(&SshCertificateCriticalOption { name: name.clone(), value: None });",
    ),
    (
        "certificate: lifetime is bounded",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "&& lifetime > MAX_CERTIFICATE_LIFETIME",
        "&& false",
    ),
    (
        "connection: handshake deadline",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "let handshake_deadline = tokio::time::sleep(HANDSHAKE_TIMEOUT);",
        "let handshake_deadline = tokio::time::sleep(Duration::from_secs(86400));",
    ),
    (
        "certificate: a host-key check names the admin who asked",
        "warpgate-protocol-ssh/src/client/mod.rs",
        ".or_else(|| self.identity_hint.clone())",
        ".or_else(|| None)",
    ),
    (
        "host key: only the hop that was asked about reports",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "matches!(self, Self::Connecting | Self::CheckedHost)",
        "true",
    ),
    (
        "vault: principal must be one harmless entry",
        "warpgate-vault/src/client.rs",
        "if principal.is_empty() || principal.contains(',') || principal.chars().any(char::is_control) {",
        "if false {",
    ),
    (
        "vault: key ID must not carry control characters",
        "warpgate-vault/src/client.rs",
        "if key_id.chars().any(char::is_control) || key_id.len() > MAX_KEY_ID {",
        "if key_id.len() > MAX_KEY_ID {",
    ),
    (
        "vault: key ID length is bounded",
        "warpgate-vault/src/client.rs",
        "if key_id.chars().any(char::is_control) || key_id.len() > MAX_KEY_ID {",
        "if key_id.chars().any(char::is_control) {",
    ),
    (
        "vault: mount and role stay one path segment",
        "warpgate-vault/src/client.rs",
        "|| !name\n            .chars()\n            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')",
        "|| false",
    ),
    (
        "vault: address must be HTTPS or loopback",
        "warpgate-vault/src/client.rs",
        "if !is_loopback {",
        "if false {",
    ),
    (
        "vault: redirects are refused",
        "warpgate-vault/src/client.rs",
        ".redirect(reqwest::redirect::Policy::none())\n            .timeout(config.timeout)\n            .build()?;\n\n        // The metadata services",
        ".timeout(config.timeout)\n            .build()?;\n\n        // The metadata services",
    ),
    (
        "vault: response bodies are bounded",
        "warpgate-vault/src/client.rs",
        "if buf.len() + chunk.len() > MAX_RESPONSE_BODY {",
        "if false {",
    ),
    (
        "vault: absurd lease refused rather than panicking",
        "warpgate-vault/src/client.rs",
        ".ok_or(VaultError::InvalidLease(seconds))?,",
        ".unwrap_or_else(|| Instant::now()),",
    ),
    (
        "vault: credential file size is capped",
        "warpgate-vault/src/client.rs",
        "if size > MAX_CREDENTIAL_FILE {",
        "if false {",
    ),
    (
        "vault: wrapping token redeemed once",
        "warpgate-vault/src/client.rs",
        "if let Some(entry) = cached.as_ref()\n            && entry.source.as_str() == cred.as_str()",
        "if let Some(entry) = cached.as_ref()\n            && false",
    ),
]

# Bare names, run from `tests/`: poetry changes into its project directory, so
# a path relative to the repository root finds nothing — and pytest reports
# "no tests ran" rather than failing, which reads exactly like every guard
# surviving. The first run of this script did precisely that.
SUITES = [
    "test_ssh_target_cert_auth.py",
    "test_vault_hostile_certs.py",
    "test_vault_hostile_target.py",
]


def run(command, **kwargs):
    return subprocess.run(command, cwd=REPO, capture_output=True, text=True, **kwargs)


def failing_tests() -> tuple[set[str], str]:
    """Which tests fail right now.

    Refuses to report anything when the run collected nothing: a suite that did
    not execute looks identical to a suite where every guard survived, and that
    is the exact confusion this script exists to expose.
    """
    result = subprocess.run(
        ["poetry", "run", "pytest", *SUITES, "-q", "--tb=no"],
        cwd=REPO / "tests",
        capture_output=True,
        text=True,
    )
    if "no tests ran" in result.stdout or "collected 0 items" in result.stdout:
        raise SystemExit(f"the suite collected nothing, so nothing was measured:\n{result.stdout[-500:]}")
    failed = {
        line.split("::")[-1].split()[0]
        for line in result.stdout.splitlines()
        if line.startswith("FAILED")
    }
    return failed, result.stdout[-400:]


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else ""
    rust_unit = run(["cargo", "test", "-p", "warpgate-vault", "-q"])
    if rust_unit.returncode != 0:
        sys.exit("the tree does not pass before mutating; fix that first")

    results = []
    for name, path, old, new in MUTATIONS:
        if only and only not in name:
            continue
        source = REPO / path
        original = source.read_text()
        if old not in original:
            results.append({"guard": name, "status": "anchor not found"})
            print(f"!! {name}: anchor not found")
            continue

        source.write_text(original.replace(old, new, 1))
        try:
            build = run(["cargo", "build", "--bin", "warpgate"])
            if build.returncode != 0:
                results.append({"guard": name, "status": "did not compile"})
                print(f"!! {name}: mutation does not compile")
                continue

            started = time.time()
            caught_by, tail = failing_tests()
            elapsed = time.time() - started

            # The Rust suite gets a say too: some guards are pinned there.
            rust = run(["cargo", "test", "-p", "warpgate-vault", "-q"])
            if rust.returncode != 0:
                caught_by.add("(cargo test -p warpgate-vault)")

            results.append(
                {
                    "guard": name,
                    "status": "caught" if caught_by else "SURVIVED",
                    "caught_by": sorted(caught_by),
                    "seconds": round(elapsed),
                }
            )
            mark = "ok" if caught_by else "SURVIVED"
            print(f"{mark:>9}  {name}  ({len(caught_by)} tests)")
            if not caught_by:
                print(f"           last output: {tail.strip()[-200:]}")
        finally:
            source.write_text(original)

    run(["cargo", "build", "--bin", "warpgate"])
    (REPO / "tests" / "mutation-matrix.json").write_text(json.dumps(results, indent=2))

    survived = [r for r in results if r["status"] == "SURVIVED"]
    print(f"\n{len(results) - len(survived)}/{len(results)} guards are caught by some test")
    for r in survived:
        print(f"  no test catches: {r['guard']}")


if __name__ == "__main__":
    main()
