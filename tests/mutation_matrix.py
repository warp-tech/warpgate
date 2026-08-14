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

import ast
import atexit
import json
import pathlib
import signal
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Crates whose unit tests can discriminate a guard. Named in one place: the
# collector and the failure reader used to carry their own copies, so a test
# in a crate only one of them knew about was invisible to the other.
RUST_CRATES = ("warpgate-vault", "warpgate-protocol-ssh", "warpgate-admin")

# Files currently rewritten in place, and their originals. A marker beside them
# so anything else touching this tree can tell — the pre-commit hook refuses to
# commit while it exists.
IN_FLIGHT: dict[str, str] = {}
LOCK = REPO / "tests" / ".matrix-running"

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
        "if expected.value.is_some() && !certificate.critical_options().contains_key(&expected.name)\n        {",
        "if false\n        {",
    ),
    (
        # The complement of the entry above: pinning must not become mandatory
        # for bare names too, or a role that sets an option only sometimes
        # cannot be configured at all.
        "certificate: a bare name permits without requiring",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "if expected.value.is_some() && !certificate.critical_options().contains_key(&expected.name)\n        {",
        "if !certificate.critical_options().contains_key(&expected.name)\n        {",
    ),
    (
        # Warpgate has no `valid_after` check — the refusal is the target's —
        # so what is guarded here is the diagnostic that sends the operator to
        # the clock rather than to the credentials.
        "certificate: a target refusal names the validity window",
        "warpgate-protocol-ssh/src/client/mod.rs",
        '(the certificate was valid from {} to {}; check the target\'s clock)",',
        '(rejected)",',
    ),
    (
        "certificate: unexpected extensions refused",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "        if !allowed_extensions.iter().any(|allowed| allowed == name) {",
        "        if false {",
    ),
    (
        "certificate: unexpected critical options refused",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "let permitted = allowed_options.iter().find(|option| &option.name == name);",
        "let permitted = Some(&SshCertificateCriticalOption { name: name.clone(), value: None });",
    ),
    # Three arms, three guards. This was one entry anchored on an `&&` chain
    # that no longer exists — the code became a match, the anchor stopped
    # matching, and the script reported the guard as covered while never once
    # disabling it. That is why a missing anchor is now fatal.
    (
        "certificate: a never-expiring certificate is refused",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "    if certificate.valid_before() == u64::MAX {",
        "    if false {",
    ),
    (
        "certificate: an unrepresentable expiry is refused",
        "warpgate-protocol-ssh/src/client/mod.rs",
        """        None => {
            return Some(
                "Vault issued a certificate with an unrepresentable expiry time".to_owned(),
            );
        }""",
        "        None => {}",
    ),
    (
        # Emptying the arm rather than guarding it with `false`: a guarded arm
        # leaves the match non-exhaustive, and a mutation that does not compile
        # measures nothing.
        "certificate: an already-expired certificate is refused",
        "warpgate-protocol-ssh/src/client/mod.rs",
        """        Some(Err(_)) => {
            return Some(
                "Vault issued a certificate that has already expired; check the clock on this host"
                    .to_owned(),
            );
        }""",
        "        Some(Err(_)) => {}",
    ),
    (
        "certificate: the returned window must match what was asked for",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "            if requested_ttl.is_some_and(|ttl| lifetime > ttl + CERTIFICATE_TTL_SLACK) =>",
        "            if false =>",
    ),
    (
        "certificate: lifetime is bounded",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "        Some(Ok(lifetime)) if lifetime > MAX_CERTIFICATE_LIFETIME => {",
        "        Some(Ok(lifetime)) if false && lifetime > MAX_CERTIFICATE_LIFETIME => {",
    ),
    (
        "connection: an untrusted jump host is refused, not traversed",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "                                return Err(ConnectionError::UntrustedJumpHost);",
        "                                {}",
    ),
    (
        "connection: a host-key check stops before authenticating",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "                            if hop.stops_after_host_key() {",
        "                            if false {",
    ),
    (
        "web-ssh: connection errors are sanitised before the user sees them",
        "warpgate-web-ssh/src/manager.rs",
        "                                    message: e.client_message(),",
        "                                    message: e.to_string(),",
    ),
    (
        "vault: certificate_ttl outside the allowed range is refused at config load",
        "warpgate-vault/src/client.rs",
        "            return Err(VaultError::InvalidCertificateTtl(ttl));",
        "            {}",
    ),
    (
        # The upper half specifically: the lower bound was checked and the
        # ceiling was not, so a mutation that drops only the ceiling has to be
        # visible on its own.
        "vault: certificate_ttl above the ceiling is refused at config load",
        "warpgate-vault/src/client.rs",
        "&& (ttl.as_secs() == 0 || ttl > MAX_CERTIFICATE_LIFETIME)",
        "&& ttl.as_secs() == 0",
    ),
    (
        "connection: the inter-hop tunnel open is bounded",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "            let channel = tokio::time::timeout(\n                HANDSHAKE_TIMEOUT,",
        "            let channel = tokio::time::timeout(\n                Duration::from_secs(86400),",
    ),
    (
        # The split. Collapsing authentication back onto the transport
        # handshake's constant is the shape it had, and a Vault slow enough to
        # exceed 30s then reads as the target failing to finish a handshake.
        "connection: authentication has its own budget",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "        (SSHTargetAuth::Certificate(_), Some(per_call)) => AUTHENTICATION_TIMEOUT",
        "        (SSHTargetAuth::Certificate(_), Some(_per_call)) if false => AUTHENTICATION_TIMEOUT",
    ),
    (
        "connection: handshake deadline",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "let handshake_deadline = tokio::time::sleep(HANDSHAKE_TIMEOUT);",
        "let handshake_deadline = tokio::time::sleep(Duration::from_secs(86400));",
    ),
    (
        # The other half of the attribution claim. `key_id_field` sanitises a
        # username on its way into the certificate; this refuses to create one
        # that would need sanitising. It shipped with no test in either language
        # and no entry here — the only check in this feature with neither.
        "users: a username cannot contain the key ID separator",
        "warpgate-admin/src/api/users.rs",
        "    !username.is_empty() && !username.contains(':')",
        "    !username.is_empty()",
    ),
    (
        # The deadline is paused while a host key is being decided on. This is
        # the line that ends the pause. Only the arming line above was guarded,
        # so the pause could be — and for a week was — permanent, and the matrix
        # reported the deadline as covered.
        "connection: the handshake deadline resumes after a host key answer",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "tokio::time::Instant::now() + HANDSHAKE_TIMEOUT,",
        "tokio::time::Instant::now() + Duration::from_secs(86400),",
    ),
    (
        "certificate: a username cannot shift the key ID fields",
        "warpgate-protocol-ssh/src/client/mod.rs",
        '    username.replace(\':\', "_")',
        "    username.to_owned()",
    ),
    (
        "certificate: a host-key check names the admin who asked",
        "warpgate-protocol-ssh/src/client/mod.rs",
        ".or_else(|| self.identity_hint.clone())",
        ".or_else(|| None)",
    ),
    (
        # And names it honestly: a token is not a person, and the first fix
        # recorded one as though it were.
        "auth: a token is not attributed as a person",
        "warpgate-common-http/src/auth.rs",
        'Self::AdminToken => "admin-token",',
        'Self::AdminToken => "admin",',
    ),
    (
        # The identity half. Reverting `role` to "is this the last hop" is the
        # shape the code had, and it gives the same answer for every chain built
        # today — which is why nothing noticed.
        "host key: the hop is chosen by identity, not by position",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "        Some(asked_about) if asked_about == hop_id => HopRole::CheckedHost,",
        "        Some(_) => HopRole::CheckedHost,",
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
        # No discriminating test yet, and the matrix says so rather than the
        # guard being absent from it: verified by an A/B on the built binary —
        # `create-user` against a namespaced mount fails with "invalid Vault
        # role or mount name" through `Services::new` and succeeds through
        # `new_without_vault`. `recover-access` takes the same path but asserts
        # an interactive terminal first, so it cannot be driven from a test
        # harness as it stands.
        "commands: break-glass does not depend on Vault",
        "warpgate/src/commands/create_user.rs",
        "Services::new_without_vault(config.clone(), None, params.clone())",
        "Services::new(config.clone(), None, params.clone())",
    ),
    (
        "vault: an unbound AWS login is called out",
        "warpgate-vault/src/client.rs",
        "        VaultAuth::Aws {\n            server_id: None, ..\n        } => Some(",
        "        VaultAuth::Aws {\n            server_id: None, ..\n        } if false => Some(",
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
        "let mut builder = reqwest::Client::builder()\n            .redirect(reqwest::redirect::Policy::none())\n            .timeout(config.timeout);",
        "let mut builder = reqwest::Client::builder()\n            .timeout(config.timeout);",
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
        # The half the stat could not see: what actually arrives, from the
        # handle already open, rather than what the filesystem claimed.
        "vault: the credential stream itself is bounded",
        "warpgate-vault/src/client.rs",
        "        if read > MAX_CREDENTIAL_FILE {",
        "        if false {",
    ),
    (
        "vault: wrapping token redeemed once",
        "warpgate-vault/src/client.rs",
        "if let Some(entry) = cached.as_ref()\n            && entry.source.as_str() == cred.as_str()",
        "if let Some(entry) = cached.as_ref()\n            && false",
    ),
]

# A mutation nothing can possibly catch: the text of a debug log line no test
# asserts on. It must come back SURVIVED.
#
# If it comes back caught, some test in the suite is failing for a reason
# unrelated to whatever is being mutated — a flake, a stale build, a broken
# fixture — and every "caught" verdict in that run is worthless, because the
# script cannot tell a guard doing its job from a suite that fails no matter
# what. The matrix exists to stop us trusting tests we have not checked; it
# needs the same treatment applied to itself.
CANARY = (
    "canary: an inert change no test can see",
    "warpgate-vault/src/client.rs",
    '"Authenticated to Vault"',
    '"Authenticated to Vault (canary)"',
)

# Which test is supposed to be the one that notices.
#
# "Some test failed" and "this guard is covered" are different claims, and this
# suite is built on top of a real sshd that enforces most of what we check for
# itself. Break the expiry guard and the connection still fails — the target
# refuses the expired certificate on its own. Break the principal guard and the
# target refuses an account it does not have. Break the unexpected-options guard
# with an option name OpenSSH does not recognise and the target refuses that too.
# In every one of those the run records "caught" and the guard is not covered by
# anything: deleting it changes nothing a test can see.
#
# So a guard is covered only when the test named after it is among the failures.
# For an integration test that means asserting on Warpgate's *own* refusal
# message, which needs a PTY — a test that only checks a non-zero exit code
# cannot tell our refusal from the target's.
#
# A guard with no entry here is reported, not skipped. Not knowing which test
# discriminates a guard is the same state as not having one.
DISCRIMINATES = {
    "certificate: key ID must match": ["test_a_certificate_with_a_different_key_id_is_refused"],
    "connection: the handshake deadline resumes after a host key answer": [
        "test_a_target_that_answers_with_a_host_key_and_then_stalls_is_given_up_on"
    ],
    "users: a username cannot contain the key ID separator": [
        "a_username_with_a_colon_would_shift_every_field_of_the_key_id"
    ],
    "connection: handshake deadline": [
        "test_a_target_that_stalls_the_handshake_is_given_up_on"
    ],
    "certificate: must certify our ephemeral key": [
        "test_certificate_issued_for_a_key_warpgate_does_not_hold"
    ],
    "certificate: a never-expiring certificate is refused": [
        "a_never_expiring_certificate_is_refused"
    ],
    "certificate: an unrepresentable expiry is refused": ["an_unrepresentable_expiry_is_refused"],
    "certificate: an already-expired certificate is refused": [
        "an_already_expired_certificate_is_refused",
        "test_expired_certificate",
    ],
    "certificate: a target refusal names the validity window": [
        "test_certificate_that_is_not_yet_valid"
    ],
    "certificate: lifetime is bounded": ["a_certificate_outliving_the_bound_is_refused"],
    "certificate: the returned window must match what was asked for": [
        "a_certificate_longer_than_the_requested_ttl_is_refused"
    ],
    "certificate: principals must be exactly the target account": [
        "test_a_certificate_naming_the_wrong_account_is_refused",
        "test_certificate_for_a_different_principal",
    ],
    "certificate: pinned critical options must be present": [
        "a_pinned_option_missing_from_the_certificate_is_refused"
    ],
    "certificate: a bare name permits without requiring": [
        "an_option_permitted_by_name_may_be_absent"
    ],
    "vault: credential file size is capped": [
        "a_credential_stream_longer_than_the_cap_is_refused_whatever_stat_says"
    ],
    "vault: certificate_ttl outside the allowed range is refused at config load": [
        "a_certificate_ttl_outside_the_allowed_range_is_refused_at_construction"
    ],
    "vault: certificate_ttl above the ceiling is refused at config load": [
        "a_certificate_ttl_outside_the_allowed_range_is_refused_at_construction"
    ],
    "certificate: unexpected extensions refused": [
        "an_extension_the_target_did_not_name_is_refused"
    ],
    "certificate: unexpected critical options refused": [
        "an_option_the_target_did_not_name_is_refused",
        "test_an_unexpected_forced_command_is_refused",
    ],
    "certificate: a username cannot shift the key ID fields": [
        "a_username_carrying_a_colon_cannot_shift_the_key_id_fields"
    ],
    "auth: a token is not attributed as a person": [
        "test_checking_a_chained_target_authenticates_only_to_the_jump_host"
    ],
    "certificate: a host-key check names the admin who asked": [
        "test_checking_a_chained_target_authenticates_only_to_the_jump_host"
    ],
    "host key: the hop is chosen by identity, not by position": [
        "test_the_host_key_check_reports_the_target_and_not_the_jump_host"
    ],
    "host key: only the hop that was asked about reports": [
        "test_the_host_key_check_reports_the_target_and_not_the_jump_host"
    ],
    "web-ssh: connection errors are sanitised before the user sees them": [
        "test_the_client_is_never_shown_the_issuers_own_words"
    ],
}

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


def check_anchors(mutations):
    """Every anchor must still match the source, before anything is run.

    An anchor that has drifted used to be recorded and stepped over, and the
    final tally counted it alongside the guards that were genuinely caught — so
    the script reported full coverage for a guard it had never once disabled.
    A guard whose anchor no longer matches is not a guard that passed; it is a
    guard that was never tested, and the run has to stop and say so.
    """
    stale = [
        (name, path)
        for name, path, old, _ in mutations
        if old not in (REPO / path).read_text()
    ]
    if stale:
        lines = "\n".join(f"  {name}\n    in {path}" for name, path in stale)
        raise SystemExit(
            f"{len(stale)} anchor(s) no longer match the source, so those guards "
            f"cannot be measured:\n{lines}\n\n"
            "Repoint them at the current code before trusting any number from "
            "this script."
        )


def write_artifact(*, partial: bool, results: list, refused: str | None):
    """The run's own record, so a claim about coverage can be checked later.

    Required by protocol amendment A2. It carries the guards, their named
    discriminators, the per-guard verdict, and — the part that was missing — the
    reason when the run refused to produce a number at all. A refusal used to
    leave nothing behind, so "the matrix says 40/40" and "the matrix refused to
    run" were indistinguishable a day later.
    """
    (REPO / "tests" / "mutation-matrix.json").write_text(
        json.dumps(
            {
                "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "head": run(["git", "rev-parse", "HEAD"]).stdout.strip(),
                "partial": partial,
                "guards_total": len(MUTATIONS),
                "guards_with_a_named_discriminator": len(DISCRIMINATES),
                "refused": refused,
                "results": results,
            },
            indent=2,
        )
    )


def existing_tests() -> set[str]:
    """Every test name this repository actually has, Python and Rust.

    Collected rather than assumed. `DISCRIMINATES` is a hand-written list of
    names, and nothing checked that any of them existed — so an entry could
    claim a guard was pinned by a test that had never been written. One was:
    `test_a_certificate_with_a_different_key_id_is_refused` appeared nowhere in
    the repository while the matrix reported on that guard for a week.

    An instrument built because we do not trust our tests was taking its own
    list of test names on faith.
    """
    names: set[str] = set()

    collected = subprocess.run(
        ["poetry", "run", "pytest", *SUITES, "--collect-only", "-q"],
        cwd=REPO / "tests",
        capture_output=True,
        text=True,
    )
    for line in collected.stdout.splitlines():
        if "::" in line:
            names.add(line.split("::")[-1].split("[")[0].strip())

    for crate in RUST_CRATES:
        listed = run(["cargo", "test", "-p", crate, "--", "--list"])
        for line in listed.stdout.splitlines():
            if line.endswith(": test"):
                names.add(line.rsplit(":", 1)[0].split("::")[-1].strip())

    return names


def check_no_duplicate_entries():
    """`DISCRIMINATES` is a dict literal, and a repeated key wins silently.

    Not hypothetical: adding an entry for a guard that already had one produced
    two keys spelled identically, naming two different tests, and Python kept
    the second. The first entry simply stopped existing — no error, no warning,
    and the count of covered guards did not move, which is the only reason it
    was noticed.

    Reads this file's own source, because by the time the dict is built the
    evidence is gone.
    """
    tree = ast.parse(pathlib.Path(__file__).read_text())
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        target = node.targets[0]
        if not (isinstance(target, ast.Name) and target.id == "DISCRIMINATES"):
            continue
        keys = [k.value for k in node.value.keys if isinstance(k, ast.Constant)]
        repeated = sorted({k for k in keys if keys.count(k) > 1})
        if repeated:
            listed = "\n".join(f"  {k}" for k in repeated)
            raise SystemExit(
                f"{len(repeated)} guard(s) have more than one entry in "
                f"DISCRIMINATES, and only the last one counts:\n{listed}"
            )

    names = [m[0] for m in MUTATIONS]
    repeated = sorted({n for n in names if names.count(n) > 1})
    if repeated:
        listed = "\n".join(f"  {n}" for n in repeated)
        raise SystemExit(f"{len(repeated)} guard name(s) are used twice:\n{listed}")


def check_discriminators(mutations):
    """Every named discriminator must resolve to a test that exists.

    Added by protocol amendment A2. The check runs before anything is mutated,
    for the same reason `check_anchors` does: a name that resolves to nothing
    cannot fail, so a guard listing one can never be reported as caught, and the
    run would spend an hour arriving at that.
    """
    have = existing_tests()
    if not have:
        raise SystemExit(
            "could not collect any test names, so the discriminator check "
            "cannot run. Refusing rather than skipping it."
        )

    missing = [
        (name, test)
        for name, *_ in mutations
        for test in DISCRIMINATES.get(name, [])
        if test not in have
    ]
    if missing:
        lines = "\n".join(f"  {test}\n    named by {name}" for name, test in missing)
        raise SystemExit(
            f"{len(missing)} named discriminator(s) do not exist:\n{lines}\n\n"
            "Write the test or repoint the entry. A name that resolves to "
            "nothing is not weaker evidence than a real test — it is none."
        )


def failing_rust_tests(crate: str) -> set[str]:
    """Which Rust tests fail, by name.

    Named rather than counted, so a guard pinned by a unit test can be credited
    to that test rather than to "the Rust suite went red", which is the same
    undiscriminating signal this script exists to stop trusting.
    """
    result = run(["cargo", "test", "-p", crate])
    return {
        line.split()[1].split("::")[-1]
        for line in result.stdout.splitlines()
        if line.startswith("test ") and line.rstrip().endswith("FAILED")
    }


def restore_everything():
    """Put every file back, whatever happened.

    `run_one`'s `finally` covers a normal return and an exception. It does not
    cover the process being killed, and this script runs for over an hour, so
    being killed is a normal way for it to end. A guard left disabled in the
    working tree then looks exactly like source code — and a `git add -A` at the
    wrong moment commits it. That happened: the redirect policy that stops
    `X-Vault-Token` following a 307 to another host was mutated away and landed
    in a commit.
    """
    for path, text in list(IN_FLIGHT.items()):
        pathlib.Path(path).write_text(text)
        IN_FLIGHT.pop(path, None)
    LOCK.unlink(missing_ok=True)


def run_one(name, path, old, new):
    """Disable one guard, run the suites, put the file back."""
    source = REPO / path
    original = source.read_text()
    IN_FLIGHT[str(source)] = original
    source.write_text(original.replace(old, new, 1))
    try:
        build = run(["cargo", "build", "--bin", "warpgate"])
        if build.returncode != 0:
            return {"guard": name, "status": "did not compile"}

        started = time.time()
        caught_by, tail = failing_tests()
        elapsed = time.time() - started

        # Both crates, by name. Only `warpgate-vault` used to be consulted, and
        # only as a yes/no — so the discriminating unit tests in
        # `warpgate-protocol-ssh` were invisible to this script, and a Rust
        # failure could not be attributed to a test.
        for crate in RUST_CRATES:
            caught_by |= failing_rust_tests(crate)

        expected = DISCRIMINATES.get(name)
        if not caught_by:
            status = "SURVIVED"
        elif expected is None:
            status = "no discriminating test named"
        elif all(test in caught_by for test in expected):
            # `all`, not `any` — protocol amendment A2. With `any`, an entry
            # naming a Rust unit test and a Python integration test was
            # satisfied by the unit test alone, and the integration test's
            # discrimination was never established while the entry implied it
            # had been. Every test an entry names now has to notice.
            status = "caught"
        else:
            # Something failed, but not the test whose name claims this guard.
            # The suite runs against a real sshd that enforces most of these
            # itself, so an unrelated failure looks exactly like coverage.
            status = "caught by something else"

        return {
            "guard": name,
            "status": status,
            "expected": expected,
            "caught_by": sorted(caught_by),
            "seconds": round(elapsed),
            "tail": "" if caught_by else tail.strip()[-200:],
        }
    finally:
        source.write_text(original)
        IN_FLIGHT.pop(str(source), None)


def main():
    LOCK.write_text("mutation_matrix is rewriting source files in place\n")
    atexit.register(restore_everything)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: sys.exit(130))

    only = sys.argv[1] if len(sys.argv) > 1 else ""
    rust_unit = run(["cargo", "test", "-p", "warpgate-vault", "-q"])
    if rust_unit.returncode != 0:
        sys.exit("the tree does not pass before mutating; fix that first")

    selected = [m for m in MUTATIONS if not only or only in m[0]]
    if not selected:
        sys.exit(f"no guard matches {only!r}")
    check_anchors(selected + [CANARY])
    check_discriminators(selected)

    # Before measuring anything, measure the instrument.
    canary = run_one(*CANARY)
    if canary["status"] != "SURVIVED":
        refused = (
            "the canary was reported as caught, which cannot be true: it only "
            "changes the text of a log line.\n"
            f"Tests that failed: {', '.join(canary.get('caught_by', []))}\n"
            "The suite is failing for reasons unrelated to the guards, so no "
            "verdict from this run means anything. Fix that first."
        )
        # A refusal is a result and gets written out like one. Amendment A2:
        # every coverage number this project published was checkable only by
        # repeating the run, and two of them were wrong.
        write_artifact(partial=bool(only), results=[], refused=refused)
        sys.exit(refused)
    print(f"{'ok':>9}  canary survived, so a 'caught' verdict means something\n")

    results = []
    for mutation in selected:
        result = run_one(*mutation)
        results.append(result)
        mark = "ok" if result["status"] == "caught" else result["status"]
        caught = len(result.get("caught_by", []))
        print(f"{mark:>9}  {result['guard']}  ({caught} tests)")
        if result.get("tail"):
            print(f"           last output: {result['tail']}")

    run(["cargo", "build", "--bin", "warpgate"])
    write_artifact(partial=bool(only), results=results, refused=None)

    caught = [r for r in results if r["status"] == "caught"]
    print(
        f"\n{len(caught)}/{len(results)} guards are caught by the test named after them"
    )
    for r in results:
        if r["status"] != "caught":
            print(f"  {r['status']}: {r['guard']}")
            if r["status"] == "caught by something else" and r["caught_by"]:
                print(f"      wanted {r['expected']}, got {r['caught_by'][:3]}")
    if len(caught) != len(results):
        # A partial result is the thing this script exists to stop us reporting
        # as a whole one.
        raise SystemExit(1)


if __name__ == "__main__":
    main()
