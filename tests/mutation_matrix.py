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

Two modes, and the routine one is `--named`. From the repository root:

    PYTHONPATH=$PWD poetry -C tests run python -m tests.mutation_matrix --named
    PYTHONPATH=$PWD poetry -C tests run python -m tests.mutation_matrix --named principal
    ... --named --changed <base>      # only guards whose anchor, or named test,
                                      # changed
    ... --named --fail-fast           # stop at the first guard that does not
                                      # discriminate, rather than spending hours
                                      # confirming the rest
    ... --named --shard 3/8           # this shard's guards only, so a sweep can
                                      # be split across CI jobs and finish

`PYTHONPATH` is not decoration. The virtualenv lives in `tests/`, so poetry has
to be pointed there, and `poetry -C tests run` executes with the working
directory *already changed* to `tests/` — at which point the `tests` package
this module belongs to is no longer importable and `-m` fails outright. A
relative `PYTHONPATH=.` resolves against that changed directory and fails the
same way. This docstring documented the shorter command for two rounds and
nobody ran it.

`--named` is the A/B the coverage number comes from: for each guard it runs only
the test named after that guard, twice — once with the guard disabled, once with
it restored — and the guard discriminates when the test fails in the first run
and passes in the second. Two runs of one test per guard.

Without the flag it asks a broader and far more expensive question — which of
*all* the tests notice the mutation — by rerunning the whole integration suite
and every crate's unit tests once per guard. That is hours, and it is the mode to
reach for when a guard has no named discriminator yet and you want to find out
what does catch it. It is not the routine invocation, and reviewers have run it
by mistake because this docstring used to name it first.
"""

import ast
import atexit
import hashlib
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Crates whose unit tests can discriminate a guard — derived from the guards
# themselves rather than typed out.
#
# It was a hand-written tuple twice over: first two copies that drifted apart,
# then one copy that was simply incomplete. A guard was moved into
# `warpgate-web-ssh`, its test went with it, and the verifier could not see the
# test because nobody thought to extend the list. It refused rather than
# guessing, which is the only reason this is a footnote and not another false
# verdict — but a list that has to be remembered will be forgotten again.
#
# Every mutation names a file, and the crate is its first path segment. A guard
# in a crate therefore brings that crate with it.
def _crates_from_mutations() -> tuple[str, ...]:
    seen = {path.split("/")[0] for _, path, _, _ in MUTATIONS}
    # `warpgate` is the binary; its unit tests are not where guards are pinned.
    return tuple(sorted(seen - {"warpgate"}))

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
        # Anchored on the whole call, not on the message alone. Replacing just
        # the string dropped its `{}` while `format!` still passed
        # `validity.0, validity.1`, so the mutation did not compile — and a
        # mutation that does not build measures nothing, which is the rule
        # stated at the top of this file and broken twice now (W-103, W-107).
        # The placeholders are kept and fed empty strings instead: the window
        # leaves the message, the code still builds.
        '''                                "Certificate authentication was rejected by the SSH target \\
                                 (the certificate was valid from {} to {}; check the target\'s clock)",
                                validity.0, validity.1''',
        '''                                "Certificate authentication was rejected by the SSH target{}{}",
                                "", ""''',
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
        "        if named.peek().is_none() {",
        "        if false {",
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
        # Anchored on the predicate, not on the call site, so a unit test can
        # decide it. The call-site mutation was pinned by an integration test
        # asking a different question entirely, and measured as not
        # discriminating — a real sshd refuses on its own, so "stopped after the
        # key" and "carried on and got refused" look identical end to end.
        "        matches!(self, Self::CheckedHost)",
        "        false",
    ),
    (
        "web-ssh: connection errors are sanitised before the user sees them",
        "warpgate-web-ssh/src/manager.rs",
        # Anchored on the named boundary rather than on a call inside the event
        # loop. A test cannot stand at that call without driving a browser
        # session, and the integration test credited with covering this guard
        # turned out to exercise the SSH path instead — measured, not suspected.
        "    error.client_message()",
        "    error.to_string()",
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
        # Disabled by neutralising the arithmetic, not by guarding the arm.
        # The previous replacement renamed the binding to `_per_call` while the
        # arm body still used `per_call`, so it did not compile — and a mutation
        # that does not build measures nothing, which is this file's own rule.
        # `cargo test` then produced no test output at all, and the verifier
        # reported "could not run" for three runs before anyone read the build
        # error. The matrix's `run_one` would have called it "did not compile",
        # which is also not "caught"; two full runs had ended on the canary
        # before reaching it, so nobody saw either.
        "        (SSHTargetAuth::Certificate(_), Some(per_call)) => AUTHENTICATION_TIMEOUT\n            .max(per_call * VAULT_CALLS_PER_AUTHENTICATION + Duration::from_secs(5)),",
        "        (SSHTargetAuth::Certificate(_), Some(per_call)) => AUTHENTICATION_TIMEOUT\n            .max(per_call * 0 + Duration::from_secs(0)),",
    ),
    (
        "connection: handshake deadline",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "let handshake_deadline = tokio::time::sleep(HANDSHAKE_TIMEOUT);",
        "let handshake_deadline = tokio::time::sleep(Duration::from_secs(86400));",
    ),
    (
        # The pin must survive a duplicate name. `.find()` took whichever entry
        # the operator typed first, so a bare row beside a pinned one cancelled
        # the pin silently while the admin UI still showed it.
        "certificate: every matching pin is enforced, not the first",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "        for option in named {",
        "        for option in named.take(1) {",
    ),
    (
        # A token is not a person, and a person may not take a token's name.
        "users: a token attribution cannot be claimed as a username",
        "warpgate-admin/src/api/users.rs",
        # Repointed after rustfmt folded the three conditions onto one line.
        "&& !TOKEN_ATTRIBUTIONS.contains(&username)",
        "&& !TOKEN_ATTRIBUTIONS.contains(&\"nobody-has-this-name\")",
    ),
    (
        # The other half of the attribution claim. `key_id_field` sanitises a
        # username on its way into the certificate; this refuses to create one
        # that would need sanitising. It shipped with no test in either language
        # and no entry here — the only check in this feature with neither.
        "users: a username cannot contain the key ID separator",
        "warpgate-admin/src/api/users.rs",
        "&& !username.contains(':')",
        "&& !username.is_empty()",
    ),
    (
        # The deadline is paused while a host key is being decided on. This is
        # the line that ends the pause. Only the arming line above was guarded,
        # so the pause could be — and for a week was — permanent, and the matrix
        # reported the deadline as covered.
        # Repointed at the policy rather than at the line that applies it.
        # The integration test that used to be named here never reached the
        # line: the stalling fixture mutes before `NEWKEYS`, and russh does not
        # call `check_server_key` until the exchange completes, so the pause and
        # the resume were both dead code in that test. Measured twice — see
        # W-116 — rather than argued.
        "connection: the handshake deadline resumes after a host key answer",
        "warpgate-protocol-ssh/src/client/mod.rs",
        # Anchored on the call, not on the constant. The constant was the anchor
        # while the test that discriminated it compared two constants, so the
        # pair agreed with each other and nothing established that either was
        # ever called.
        """fn resume_after_host_key_answer(deadline: Pin<&mut tokio::time::Sleep>) {
    deadline.reset(tokio::time::Instant::now() + once_the_host_key_is_answered());
}""",
        """fn resume_after_host_key_answer(deadline: Pin<&mut tokio::time::Sleep>) {
    deadline.reset(tokio::time::Instant::now() + while_a_host_key_answer_is_outstanding());
}""",
    ),
    (
        "certificate: a username cannot shift the key ID fields",
        "warpgate-protocol-ssh/src/client/mod.rs",
        # Repointed three times: when the attribution substitution joined this
        # function, when it left for `user_key_id_field` because it was renaming
        # the gateway itself, and when the substitution became a percent
        # encoding because `root:admin` and `root_admin` collided under it.
        # Each move was caught by `check_anchors` and by nothing else — a guard
        # whose anchor has gone stale is reported as measured while never once
        # being disabled, which is the failure this whole file exists to stop.
        """    name.replace('%', "%25").replace(':', "%3A")""",
        """    name.to_owned()""",
    ),
    (
        "certificate: a host-key check names the admin who asked",
        "warpgate-protocol-ssh/src/client/mod.rs",
        # Repointed when the hint stopped being a bare string: the gateway's own
        # attribution and a person's name are now carried apart.
        "            None => self.identity_hint.as_ref().map(|hint| match hint {",
        "            None => None.map(|hint: &IdentityHint| match hint {",
    ),
    (
        # And names it honestly: a token is not a person, and the first fix
        # recorded one as though it were.
        "auth: a token is not attributed as a person",
        "warpgate-common-http/src/auth.rs",
        'pub const TOKEN_ATTRIBUTIONS: [&str; 2] = ["admin-token", "cluster-token"];',
        'pub const TOKEN_ATTRIBUTIONS: [&str; 2] = ["admin", "cluster"];',
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
        # Repointed when the rule moved to `warpgate-common`, so the admin API
        # could refuse at save time by the same test the signing path applies.
        "vault: mount and role stay one path segment",
        "warpgate-common/src/config/target.rs",
        "        && name\n            .chars()\n            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')",
        "        && true",
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
        "vault: address must be HTTPS",
        "warpgate-vault/src/client.rs",
        'if parsed.scheme() != "https" {',
        'if false {',
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
    # `vault: credential file size is capped` used to be here and is not a
    # guard. Measured, not argued: with the check disabled,
    # `an_oversized_regular_file_is_refused` still passes, because the stream
    # bound eight lines below refuses the same file. It has no input of its
    # own — `read_credential` stats the open handle rather than the path, so
    # there is no window in which the two could disagree, and a FIFO, the one
    # source that lies about its size, is caught by the stream bound alone.
    #
    # So it is an early-out that avoids reading 16 KB before refusing, and
    # listing it as a security guard inflated the count by one while
    # guaranteeing a permanent failure in any honest verification. Removed
    # rather than left failing: the entry was a classification error, and
    # keeping a non-guard in the list to avoid appearing to remove a failure
    # would be the same dishonesty pointed the other way.
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
    (
        # The gateway's own attribution is reachable as a username through five
        # of the six paths that create one. Held where the key ID is built, so
        # which path created the user stops mattering.
        "certificate: a username cannot impersonate the gateway's attribution",
        "warpgate-protocol-ssh/src/client/mod.rs",
        'if is_reserved_key_id_field(&field) {\n        return format!("{field}_");\n    }',
        'if false {\n        return format!("{field}_");\n    }',
    ),
    (
        # Ours, found by unskipping the integration test in round J. Rendering
        # the validity window for the diagnostic panicked on a never-expiring
        # certificate, in a tokio worker, before the check that refuses one.
        "certificate: describing a far-future expiry cannot panic",
        "warpgate-protocol-ssh/src/client/mod.rs",
        """    let mut rendered = String::new();
    if write!(rendered, "{}", humantime::format_rfc3339_seconds(at)).is_err() {
        return "a date beyond any this can render".to_owned();
    }
    rendered""",
        """    humantime::format_rfc3339_seconds(at).to_string()""",
    ),
    (
        # Raised externally, round J: an operator checking a host key saw
        # `SSH protocol error` both for a host that could not be reached and for
        # one whose key is not trusted — one sentence for two different jobs.
        "connection: unreachable and untrusted do not read alike",
        "warpgate-protocol-ssh/src/client/mod.rs",
        """            ConnectionError::Io(e) | ConnectionError::Ssh(russh::Error::IO(e)) => {
                format!(
                    "Could not open an SSH connection to the target: {}",
                    unreachable_reason(e.kind())
                )
            }""",
        """            ConnectionError::Io(_) | ConnectionError::Ssh(russh::Error::IO(_)) => {
                "SSH protocol error".to_string()
            }""",
    ),
    (
        # Raised externally, round J: the sanitiser had no test at all, and the
        # nearest one asserts a string that appears in an unrelated variant's
        # `Display` too, so it passes with the sanitising removed.
        "error surfacing: internal error text never reaches a client message",
        "warpgate-protocol-ssh/src/client/mod.rs",
        """            ConnectionError::Warpgate(_) => "Internal connection error".to_string(),""",
        """            ConnectionError::Warpgate(e) => e.to_string(),""",
    ),
    (
        # Raised externally, round J: the whole authentication step was bounded
        # by a budget that grows with `vault.timeout`, so a target that went
        # quiet after receiving its certificate was waited on for as long as
        # Vault was allowed to be slow.
        "connection: the target's own USERAUTH answer is bounded",
        "warpgate-protocol-ssh/src/client/mod.rs",
        """    tokio::time::timeout(bound, what)
        .await
        .map_err(|_| ConnectionError::TargetAuthenticationTimeout)?
        .map_err(ConnectionError::from)""",
        """    what.await.map_err(ConnectionError::from)""",
    ),
    (
        # Raised externally, round J: the substitution mapped `root:admin` and
        # `root_admin` onto one field, so the log line this feature exists to
        # produce could name a person who did not connect.
        "certificate: two usernames cannot produce one key ID",
        "warpgate-protocol-ssh/src/client/mod.rs",
        """    name.replace('%', "%25").replace(':', "%3A")""",
        """    name.replace(':', "_")""",
    ),
    (
        # The reserved names lived in two places and only one was consulted.
        # `UNATTRIBUTED` goes into the same field, written by the same code, and
        # a user of that name read as a session with no user recorded at all.
        "certificate: the unattributed placeholder cannot be claimed by a user",
        "warpgate-protocol-ssh/src/client/mod.rs",
        """    TOKEN_ATTRIBUTIONS.contains(&field) || field == UNATTRIBUTED""",
        """    TOKEN_ATTRIBUTIONS.contains(&field)""",
    ),
    (
        # Validated at connect time already; the guard is that the admin API
        # refuses the same name at save time, where the operator can fix it.
        "admin: a Vault role the signing path would refuse is refused on save",
        "warpgate-admin/src/api/targets.rs",
        "        .is_none_or(|role| warpgate_common::vault_name_is_well_formed(role))",
        "        .is_none_or(|_| true)",
    ),
    (
        # The one response-side property that had no check at all: every other
        # asks whether the certificate matches the request, none asked who
        # signed it.
        "certificate: the signing CA must be the pinned one",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "    if certificate.signature_key() == expected.key_data() {\n        return None;\n    }",
        "    if true {\n        return None;\n    }",
    ),
    (
        "connection: a chain missing the host asked about is refused",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "    check_target.is_none_or(|asked_about| hops.contains(&asked_about))",
        "    check_target.is_none_or(|asked_about| asked_about == asked_about)",
    ),
    (
        "certificate: a refused option name is escaped before it reaches the terminal",
        "warpgate-protocol-ssh/src/client/mod.rs",
        "carrying the critical option {name:?}, which this target does not allow",
        "carrying the critical option {name}, which this target does not allow",
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
RUST_CRATES = _crates_from_mutations()

# A guard with no entry here is reported, not skipped. Not knowing which test
# discriminates a guard is the same state as not having one.
DISCRIMINATES = {
    "certificate: a refused option name is escaped before it reaches the terminal": [
        "test_a_hostile_option_name_cannot_write_to_the_terminal"
    ],
    "certificate: key ID must match": ["test_a_certificate_with_a_different_key_id_is_refused"],
    "connection: the handshake deadline resumes after a host key answer": [
        "answering_a_host_key_question_puts_the_targets_own_bound_back"
    ],
    # The seventeen that had no entry. Most already had a discriminating test —
    # it had simply never been written down, which under the criterion in §8 is
    # the same state as having none: nothing established that the test noticing
    # was the test named after the guard.
    "certificate: must be a user certificate": [
        "test_a_host_certificate_is_not_offered_to_the_target"
    ],
    # Its own test since W-119. It shared one with the two host-key guards
    # below, which need the opposite starting condition — a jump host that *is*
    # trusted — so one test was setting up both worlds and the refusal it
    # asserted was only ever the first half of a longer story.
    "connection: an untrusted jump host is refused, not traversed": [
        "test_an_untrusted_jump_host_is_refused_rather_than_traversed"
    ],
    "connection: a host-key check stops before authenticating": [
        "a_host_key_check_stops_at_the_hop_it_asked_about",
        "each_role_reports_and_stops_as_its_name_says",
    ],
    "connection: the inter-hop tunnel open is bounded": [
        "test_a_jump_host_that_never_opens_the_tunnel_is_given_up_on"
    ],
    "connection: authentication has its own budget": [
        "a_certificate_target_gets_a_budget_that_fits_its_vault_calls"
    ],
    "vault: principal must be one harmless entry": ["test_principal_validation"],
    "vault: key ID must not carry control characters": ["test_key_id_validation"],
    # Same source line as the entry above, opposite half. `test_key_id_validation`
    # had no length case until this round, so a mutation dropping only the bound
    # was caught by nothing while the line looked covered.
    "vault: key ID length is bounded": ["test_key_id_validation"],
    "vault: mount and role stay one path segment": ["test_segment_validation"],
    "commands: break-glass does not depend on Vault": [
        "test_break_glass_user_creation_does_not_depend_on_vault"
    ],
    "vault: an unbound AWS login is called out": ["an_unbound_aws_login_is_called_out"],
    "vault: address must be HTTPS": ["test_address_validation"],
    "vault: redirects are refused": [
        "test_a_redirect_never_carries_the_token_to_another_host"
    ],
    "vault: response bodies are bounded": [
        "test_an_oversized_success_body_is_refused_rather_than_buffered"
    ],
    "vault: absurd lease refused rather than panicking": [
        "test_an_absurd_lease_is_refused_rather_than_panicking"
    ],
    # One test each, because one test could not do both. The caveat that used
    # to sit here claimed this entry "does discriminate the line the guard
    # names"; `verify_named_rust` measured that claim and it was false. An
    # oversized regular file is refused by the `stat` early-out and by the
    # stream bound alike, so disabling either left the other to catch it and
    # neither guard was evidenced. A FIFO reports a size of zero, which is the
    # only input the stream bound has to itself.
    "vault: the credential stream itself is bounded": [
        "only_the_stream_bound_can_refuse_a_source_that_lies_about_its_size"
    ],
    "vault: wrapping token redeemed once": [
        "test_a_wrapping_token_is_redeemed_once_and_the_secret_id_reused"
    ],
    "certificate: every matching pin is enforced, not the first": [
        "a_bare_duplicate_does_not_cancel_a_pinned_value",
        "conflicting_pins_refuse_everything_rather_than_picking_one",
    ],
    "users: a token attribution cannot be claimed as a username": [
        "a_username_with_a_colon_would_shift_every_field_of_the_key_id"
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
    "certificate: a username cannot impersonate the gateway's attribution": [
        "a_username_cannot_impersonate_the_gateways_own_attribution"
    ],
    "certificate: describing a far-future expiry cannot panic": [
        "a_far_future_expiry_is_described_rather_than_panicked_on"
    ],
    "connection: unreachable and untrusted do not read alike": [
        "an_unreachable_target_does_not_read_like_an_untrusted_key"
    ],
    "error surfacing: internal error text never reaches a client message": [
        "no_internal_error_text_reaches_a_client_message"
    ],
    "connection: the target's own USERAUTH answer is bounded": [
        "a_target_that_never_answers_userauth_is_given_up_on"
    ],
    "certificate: two usernames cannot produce one key ID": [
        "two_usernames_cannot_collide_in_a_key_id"
    ],
    "certificate: the unattributed placeholder cannot be claimed by a user": [
        "a_username_cannot_impersonate_the_unattributed_placeholder"
    ],
    "admin: a Vault role the signing path would refuse is refused on save": [
        "a_role_the_signing_path_would_refuse_is_refused_at_save_time"
    ],
    "certificate: the signing CA must be the pinned one": [
        "a_certificate_from_an_unpinned_ca_is_refused"
    ],
    "connection: a chain missing the host asked about is refused": [
        "a_chain_without_the_host_asked_about_cannot_answer"
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
    # These two do share a discriminator, and it was looked at rather than left
    # alone (W-119). They are one decision read two ways — which hop is the
    # answer, and which hops may speak — and on a chain of two every mutation of
    # either ends in the same observation: the endpoint answers with the jump
    # host's key. Separating them end to end would take an observation neither
    # the endpoint nor the target makes; the unit test that pins the decision
    # itself, `each_role_reports_and_stops_as_its_name_says`, is equally unable
    # to tell them apart, and for the same reason.
    "host key: the hop is chosen by identity, not by position": [
        "test_the_host_key_check_reports_the_target_and_not_the_jump_host"
    ],
    "host key: only the hop that was asked about reports": [
        "test_the_host_key_check_reports_the_target_and_not_the_jump_host"
    ],
    "web-ssh: connection errors are sanitised before the user sees them": [
        "a_browser_never_sees_the_error_s_own_words"
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


def _test_name_from_summary_line(line: str, head: str) -> str | None:
    """The test named by one of pytest's short-summary lines.

    Read `line.split("::")[-1].split()[0]` and it looks right until a test
    fails on an assertion whose message contains a Rust module path. A summary
    line is `FAILED <nodeid> - <message>`, the message here is a slice of
    Warpgate's own log, and the log is full of `warpgate_common_http::logging`.
    Splitting on the *last* `::` then returns a fragment of that message, the
    test is not recognised as having failed, and the run records it as passed —
    which is how four guards that discriminate were reported as guards that do
    not. The nodeid is what to read, and it ends at the first ` - `.
    """
    nodeid = line[len(head):].strip().split(" - ", 1)[0].strip()
    if not nodeid:
        return None
    # `test_x[a b]` is one nodeid with a space in it; the parameters are not
    # part of the name a guard names.
    return nodeid.split("::")[-1].split("[", 1)[0].strip() or None


def _gateway_fingerprint() -> str | None:
    """Whether the binary the tests will run is the one just built.

    An A/B where both halves ran the same binary is not an A/B, and it reports
    `does not discriminate` — the guard\'s own test passing with the guard off —
    which is indistinguishable from a real coverage hole. Two guards were
    reported that way by the first CI sweep while both discriminated locally,
    and nothing in the run recorded enough to tell the two explanations apart.
    """
    binary = REPO / "target" / "debug" / "warpgate"
    if not binary.exists():
        return None
    digest = hashlib.sha256()
    with binary.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()[:16]


def run_named_only(
    tests: list[str], crates=None
) -> tuple[set[str], set[str], dict[str, str]]:
    """Run only the given tests. Returns (passed, failed, unclear), by name.

    `unclear` is the third answer this used to lack. A test can be skipped,
    error in a fixture, be deselected, or never be collected at all, and none
    of those is a pass — but all of them were recorded as one, because the
    only thing read was the list of failures.

    The whole suite is not run. That is the point: `run_one` runs everything
    because it asks "which tests notice", and the answer to that question is
    worth an hour only while the guard has no named discriminator. Once it has
    one, the question in §8 is narrower — does *this* test notice — and one test
    answers it.

    It is also the way past W-25b. Two full runs ended on the canary with five
    unrelated failures that passed again in isolation, so the suite is not
    stable under the load a full sweep creates. Running one test creates no such
    load, and the A/B below is decisive on its own: the named test must pass
    before the mutation and fail after it. A test that was already failing
    cannot be mistaken for a guard being caught, because the "before" half
    catches that first.
    """
    passed: set[str] = set()
    failed: set[str] = set()
    unclear: dict[str, str] = {}

    crates = crates or list(RUST_CRATES)
    rust = [t for t in tests if not t.startswith("test_") or _is_rust(t, crates)]
    python = [t for t in tests if t not in rust]

    # Stops as soon as every wanted test has been located. Without this, a guard
    # whose one discriminator lives in the first crate still built the test
    # binary of every other crate, to ask each whether it also owned a name that
    # had already been found.
    outstanding = set(rust)
    for crate in crates:
        if not outstanding:
            break
        wanted = [t for t in outstanding if t in _crate_tests(crate)]
        if not wanted:
            continue
        outstanding -= set(wanted)
        for name in wanted:
            result = run(["cargo", "test", "-p", crate, "--", "--exact", *_paths(crate, name)])
            (failed if result.returncode != 0 else passed).add(name)

    if python:
        result = subprocess.run(
            ["poetry", "run", "pytest", *SUITES, "-q", "--tb=no", "-rA",
             "-p", "no:randomly", "-k", " or ".join(python)],
            cwd=REPO / "tests",
            capture_output=True,
            text=True,
            # The suites' `timeout` fixture defaults to 10 seconds and CI sets
            # 120. Left at the default, a loaded machine times a test out
            # before the mutation is even applied, and the guard is reported
            # `already failing` — an accusation against the guard for what is
            # only the harness being impatient. Measured: two guards reported
            # that way in a full run both discriminate when run alone.
            env={**os.environ, "TIMEOUT": os.environ.get("TIMEOUT", "120")},
        )
        # Classify explicitly. Reading only the `FAILED` lines and calling
        # everything else passed made a skipped, errored, deselected or
        # never-collected test indistinguishable from a passing one — the same
        # confusion `failing_tests` already refuses for a whole suite, left open
        # for a single test. `-rA` makes pytest state an outcome per test, and a
        # name pytest never mentions is recorded as unknown rather than passed.
        outcome = {}
        for line in result.stdout.splitlines():
            head = line.split(" ", 1)[0]
            if head in ("PASSED", "FAILED", "ERROR", "SKIPPED", "XFAIL", "XPASS"):
                name = _test_name_from_summary_line(line, head)
                if name:
                    outcome[name] = head
        # A skip is the one outcome pytest's short summary does not attribute:
        # the line is `SKIPPED [1] <file>:<line>: <reason>`, with no nodeid in
        # it. So a name that goes unreported while skips were printed is named
        # as probably skipped rather than as a blank.
        skips = [
            line for line in result.stdout.splitlines() if line.startswith("SKIPPED")
        ]
        for name in python:
            verdict = outcome.get(name)
            if verdict == "FAILED":
                failed.add(name)
            elif verdict == "PASSED":
                passed.add(name)
            elif verdict:
                unclear[name] = verdict
            elif skips:
                unclear[name] = f"not reported; the run skipped {len(skips)}: {skips[0][:90]}"
            else:
                unclear[name] = "never reported by pytest"
        if unclear:
            # Kept because the reason a test did not report is in pytest's own
            # output, and every run so far has thrown that output away.
            unclear["pytest output"] = result.stdout[-1200:]

    return passed, failed, unclear


_RUST_TEST_CACHE: dict[str, dict[str, str]] = {}


def _crate_tests(crate: str) -> dict[str, str]:
    """Test name to its full `module::path::name`, for `--exact`."""
    if crate not in _RUST_TEST_CACHE:
        listed = run(["cargo", "test", "-p", crate, "--", "--list"])
        paths = {}
        for line in listed.stdout.splitlines():
            if line.endswith(": test"):
                path = line.rsplit(":", 1)[0].strip()
                paths.setdefault(path.split("::")[-1], path)
        _RUST_TEST_CACHE[crate] = paths
    return _RUST_TEST_CACHE[crate]


def _paths(crate: str, name: str) -> list[str]:
    path = _crate_tests(crate).get(name)
    return [path] if path else [name]


def _crates_nearest(path: str) -> list[str]:
    """`RUST_CRATES`, with the crate a guard lives in tried first.

    Listing a crate's tests builds that crate's test binary, so the order these
    are consulted in is most of the cost of a small run. A guard's discriminator
    is usually — not always — in the guard's own crate, so trying that one first
    turns six builds into one in the common case while leaving the uncommon one
    correct.
    """
    own = path.split("/")[0]
    if own not in RUST_CRATES:
        return list(RUST_CRATES)
    return [own] + [c for c in RUST_CRATES if c != own]


def _is_rust(name: str, crates=None) -> bool:
    return any(name in _crate_tests(crate) for crate in (crates or RUST_CRATES))


# Guards added or repointed in round J. A scheduling hint only: it puts the
# least-established guards first so a `--fail-fast` run reaches them in minutes
# rather than hours. Drifting out of date costs nothing here, unlike
# `DISCRIMINATES`, where a stale name is a guard that cannot be measured.
RECENT_GUARDS = frozenset({
    "certificate: two usernames cannot produce one key ID",
    "certificate: the unattributed placeholder cannot be claimed by a user",
    "certificate: a username cannot shift the key ID fields",
    "certificate: a username cannot impersonate the gateway's attribution",
    "certificate: describing a far-future expiry cannot panic",
    "connection: the target's own USERAUTH answer is bounded",
    "connection: unreachable and untrusted do not read alike",
    "connection: the handshake deadline resumes after a host key answer",
    "error surfacing: internal error text never reaches a client message",
})


def _needs_gateway_binary(tests, crates) -> bool:
    """Whether measuring this guard runs the gateway at all.

    A Rust discriminator is compiled and run by `cargo test -p <crate>`, which
    builds its own test binary from the mutated source and never looks at
    `target/debug/warpgate`. Building the gateway for those guards — 33 of the
    53 — was work whose result nothing read.
    """
    return any(t.startswith("test_") and not _is_rust(t, crates) for t in tests)


def verify_named(mutations, fail_fast=False):
    """A/B every guard against the test named after it, one at a time.

    Reports per guard: `discriminates`, `does not discriminate` (the named test
    passed with the guard disabled, so it is not evidence for it), `already
    failing` (the baseline was red, so nothing could be concluded), or `did not
    compile`.
    """
    results = []
    total = len(mutations)
    started_at = time.time()

    def stamp() -> str:
        """Elapsed since measurement began, as `h:mm:ss`.

        Wall-clock duration is the only thing anyone asks of a run this long —
        how far in, how much left — and it was the one thing the output did not
        say. Elapsed rather than a clock time, because the interesting quantity
        is the cost of a guard, not the hour it happened to fall in.
        """
        seconds = int(time.time() - started_at)
        return f"{seconds // 3600}:{seconds // 60 % 60:02d}:{seconds % 60:02d}"

    def record(result):
        """Appended *and printed*, as each guard finishes.

        Everything used to be printed after the loop returned, so a run said
        nothing at all until it was over. A 34-guard sweep is well over an hour
        here, and for that hour the only thing distinguishing progress from a
        hang was `ps`. An instrument that cannot be told apart from a stuck one
        gets killed, and two of mine were.
        """
        results.append(result)
        result["at"] = stamp()
        print(
            f"[{len(results):>2}/{total}] {result['status']:>26}  "
            f"{result['guard']}  ({stamp()})",
            flush=True,
        )
        return result

    # `target/debug/warpgate` is left holding the last mutation applied to it,
    # because restoring a source file does not rebuild the binary compiled from
    # it. The next guard's *baseline* then ran the previous guard's mutated
    # gateway, and reported `already failing` for a tree that was fine — twice
    # in one sweep, on guards 29 and 31. Raised by Antigravity as W-152, and it
    # invalidated the baseline half of every integration guard's A/B.
    binary_is_mutated = False

    for index, (name, path, old, new) in enumerate(mutations, start=1):
        expected = DISCRIMINATES.get(name)
        if not expected:
            print(f"[{index:>2}/{total}] measuring       {name}", flush=True)
            record({"guard": name, "status": "no discriminating test named"})
            continue

        nearest = _crates_nearest(path)
        needs_binary = _needs_gateway_binary(expected, nearest)
        kind = "integration" if needs_binary else "unit"
        print(f"[{index:>2}/{total}] measuring       {name}  ({kind}, {stamp()})", flush=True)

        if needs_binary and binary_is_mutated:
            print(f"[{index:>2}/{total}]   rebuilding the gateway from clean source", flush=True)
            run(["cargo", "build", "--bin", "warpgate"])
            binary_is_mutated = False

        print(f"[{index:>2}/{total}]   baseline", flush=True)
        before_pass, before_fail, before_unclear = run_named_only(expected, nearest)
        if before_fail:
            record({
                "guard": name,
                "status": "already failing",
                "tests": sorted(before_fail),
            })
            continue
        # The precondition is that the named test *passes* before the mutation.
        # A test that was skipped, errored or never collected has not met it,
        # and measuring the other half of the A/B against it produces a verdict
        # about nothing. This used to read as a clean baseline.
        if before_unclear:
            record({
                "guard": name,
                "status": "no baseline",
                "expected": expected,
                "unclear_at_baseline": before_unclear,
            })
            continue

        source = REPO / path
        original = source.read_text()
        IN_FLIGHT[str(source)] = original
        source.write_text(original.replace(old, new, 1))
        try:
            if needs_binary:
                print(f"[{index:>2}/{total}]   building the gateway with the guard off", flush=True)
                before_build = _gateway_fingerprint()
                build = run(["cargo", "build", "--bin", "warpgate"])
                binary_is_mutated = True
                if build.returncode != 0:
                    record({"guard": name, "status": "did not compile"})
                    continue
                after_build = _gateway_fingerprint()
                if after_build is not None and after_build == before_build:
                    record({
                        "guard": name,
                        "status": "the mutation never reached the binary",
                        "expected": expected,
                        "fingerprint": after_build,
                        "build_output": build.stdout[-600:] + build.stderr[-600:],
                    })
                    continue
            print(f"[{index:>2}/{total}]   testing with the guard off", flush=True)
            after_pass, after_fail, after_unclear = run_named_only(expected, nearest)
            # `all`, per A2: every test the entry names has to notice.
            status = (
                "discriminates"
                if set(expected) <= after_fail
                else "no verdict"
                if after_unclear
                else "does not discriminate"
            )
            entry = {
                "guard": name,
                "status": status,
                "expected": expected,
                "failed_with_guard_off": sorted(after_fail),
                "passed_with_guard_off": sorted(after_pass),
            }
            # Only for the verdicts that need explaining. A guard that
            # discriminated needs no forensics; one that did not is exactly
            # where the run has been unable to say why.
            if status != "discriminates":
                entry["unclear_with_guard_off"] = after_unclear
                entry["gateway_built_for_this_guard"] = bool(needs_binary)
            record(entry)
        finally:
            source.write_text(original)
            IN_FLIGHT.pop(str(source), None)

        if fail_fast and results[-1]["status"] != "discriminates":
            print(
                f"\nstopping at [{index}/{total}] because --fail-fast was asked "
                f"for and this guard came back {results[-1]['status']!r}.\n"
                f"{len(results)} of {total} measured; the rest are unknown, not "
                f"passing.",
                flush=True,
            )
            break

    # The tree is clean by now but the binary is not, and whatever runs next
    # deserves one built from the source that is actually on disk.
    if binary_is_mutated:
        print("rebuilding the gateway from clean source", flush=True)
        run(["cargo", "build", "--bin", "warpgate"])
    return results


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
        name
        for line in result.stdout.splitlines()
        if line.startswith("FAILED")
        # Same reason as in `run_named_only`: the last `::` on a summary line
        # belongs to whatever Rust module path the assertion message quoted.
        for name in [_test_name_from_summary_line(line, "FAILED")]
        if name
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


def _package_of(crate_dir: str) -> str:
    """The Cargo package name for a directory, read rather than assumed.

    They match in this workspace today. Reading it costs one line and removes a
    convention from the set of things a future rename can quietly break.
    """
    manifest = (REPO / crate_dir / "Cargo.toml").read_text()
    for line in manifest.splitlines():
        if line.startswith("name"):
            return line.split("=", 1)[1].strip().strip('"')
    raise SystemExit(f"{crate_dir}/Cargo.toml names no package")


def check_replacements_build(mutations, in_flight):
    """Every replacement must compile, before anything is measured.

    The rule is stated at the top of this file and has been broken twice. W-103
    renamed a binding the arm body still used; W-107 dropped the `{}` from a
    format string that still passed two arguments. Both were found hours into a
    run, when the guard's turn finally came and the build failed — and a guard
    whose mutation does not build has not been measured, whatever the tally
    says.

    Checked in as few passes as the matrix allows, not one per guard: the
    replacements are applied together and the packages they touch are checked
    in one `cargo check`, so the whole matrix costs two builds rather than
    forty-seven. The binary crate is included even though it holds no
    discriminating tests, because "it compiles" is a claim about all of the
    code, not the tested part.

    More than one pass is needed because some guards deliberately share an
    anchor. `certificate: pinned critical options must be present` and
    `certificate: a bare name permits without requiring` disable the same line
    in opposite directions — one drops the requirement, the other makes it
    unconditional — and neither is redundant. Two mutations over one span
    cannot be applied at once, so they go in different rounds. The first
    version of this check applied everything in one pass and refused the whole
    matrix on exactly that, calling a deliberate pair a collision.

    An anchor that vanishes *within* a round is still a refusal: that is an
    overlap nobody declared, and two guards that quietly rewrite each other
    cannot both be measured.
    """
    # Guards sharing an anchor go in separate rounds; everything else rides
    # along in the first.
    rounds: list[list] = []
    seen: dict[tuple[str, str], int] = {}
    for mutation in mutations:
        _, path, old, _ = mutation
        turn = seen.get((path, old), 0)
        seen[(path, old)] = turn + 1
        while len(rounds) <= turn:
            rounds.append([])
        rounds[turn].append(mutation)

    packages = []
    for crate in sorted({path.split("/")[0] for _, path, _, _ in mutations}):
        packages += ["-p", _package_of(crate)]

    for round_number, batch in enumerate(rounds, start=1):
        _check_one_round(batch, packages, in_flight, round_number, len(rounds))


def _check_one_round(mutations, packages, in_flight, round_number, rounds):
    print(
        f"    [{round_number}/{rounds}] compiling {len(mutations)} replacement(s)",
        flush=True,
    )
    touched: dict[Path, str] = {}
    collided = []
    try:
        for name, path, old, new in mutations:
            source = REPO / path
            if source not in touched:
                touched[source] = source.read_text()
                in_flight[str(source)] = touched[source]
            current = source.read_text()
            if old not in current:
                collided.append((name, path))
                continue
            source.write_text(current.replace(old, new, 1))

        if collided:
            lines = "\n".join(f"  {name}\n    in {path}" for name, path in collided)
            raise SystemExit(
                f"{len(collided)} anchor(s) vanished once their neighbours in "
                f"the same round were applied, so those guards overlap without "
                f"saying so and cannot both be measured:\n{lines}"
            )

        built = run(["cargo", "check", "--all-targets", *packages])
        if built.returncode != 0:
            errors = [
                line for line in built.stderr.splitlines() if line.startswith("error")
            ]
            raise SystemExit(
                f"a replacement does not compile (round {round_number} of "
                f"{rounds}), so the guard it belongs to cannot be "
                f"measured:\n"
                + "\n".join(f"  {line}" for line in errors[:10])
                + "\n\nRepoint it at something that builds before trusting any "
                "number from this script."
            )
    finally:
        for source, original in touched.items():
            source.write_text(original)
            in_flight.pop(str(source), None)


def write_artifact(
    *,
    results: list,
    refused: str | None,
    selected: int,
    mode: str = "full",
    shard: str | None = None,
):
    """The run's own record, so a claim about coverage can be checked later.

    Required by protocol amendment A2. It carries the guards, their named
    discriminators, the per-guard verdict, and — the part that was missing — the
    reason when the run refused to produce a number at all. A refusal used to
    leave nothing behind, so "the matrix says 40/40" and "the matrix refused to
    run" were indistinguishable a day later.

    Every count here is a count of *this run*. The first version of this file
    reported `len(MUTATIONS)` and `len(DISCRIMINATES)` — the height of the guard
    table and the number of declarations in it — under names that read as
    results. A four-guard run and a full sweep emitted the same "53 / 53", and
    `partial` was set from whether a `--named <substring>` filter was passed, so
    a `--changed` subset called itself complete. An artifact that cannot tell a
    subset from a sweep is worse than none: it invites the number to be quoted.
    """
    (REPO / "tests" / "mutation-matrix.json").write_text(
        json.dumps(
            {
                "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "head": run(["git", "rev-parse", "HEAD"]).stdout.strip(),
                "mode": mode,
                "shard": shard,
                "partial": len(results) < len(MUTATIONS),
                "guards_defined": len(MUTATIONS),
                "guards_selected": selected,
                "guards_measured": len(results),
                "guards_that_discriminate": sum(
                    1
                    for r in results
                    # `--named` calls the verdict "discriminates"; the full
                    # sweep calls the same verdict "caught".
                    if r.get("status") in ("discriminates", "caught")
                ),
                "refused": refused,
                "results": results,
            },
            indent=2,
        )
    )


def _python_test_names() -> set[str]:
    names: set[str] = set()
    print("    collecting the Python suites", flush=True)
    collected = subprocess.run(
        ["poetry", "run", "pytest", *SUITES, "--collect-only", "-q"],
        cwd=REPO / "tests",
        capture_output=True,
        text=True,
    )
    for line in collected.stdout.splitlines():
        if "::" in line:
            names.add(line.split("::")[-1].split("[")[0].strip())
    return names


def _rust_test_names(crates) -> set[str]:
    names: set[str] = set()
    crates = list(crates)
    for index, crate in enumerate(crates, start=1):
        # One line per crate, because each of these builds that crate's test
        # binary and the six together run for half an hour. The phase used to
        # announce itself once and then go quiet for all of it, which is the
        # same fault as the sweep's, one level down.
        print(f"    [{index}/{len(crates)}] listing tests in {crate}", flush=True)
        listed = run(["cargo", "test", "-p", crate, "--", "--list"])
        for line in listed.stdout.splitlines():
            if line.endswith(": test"):
                names.add(line.rsplit(":", 1)[0].split("::")[-1].strip())
    return names


def existing_tests(mutations=None) -> set[str]:
    """Every test name this repository actually has, Python and Rust.

    Collected rather than assumed. `DISCRIMINATES` is a hand-written list of
    names, and nothing checked that any of them existed — so an entry could
    claim a guard was pinned by a test that had never been written. One was:
    `test_a_certificate_with_a_different_key_id_is_refused` appeared nowhere in
    the repository while the matrix reported on that guard for a week.

    An instrument built because we do not trust our tests was taking its own
    list of test names on faith.

    Scoped to what is being checked, when a selection is given. Collecting
    everything costs a full pytest collection plus one `cargo test --list` per
    crate — eight of them, each building that crate's test binary — and that
    fixed cost was paid identically for one guard and for forty-seven. A
    reviewer ran a single guard and waited twenty-five minutes before the first
    A/B, which is most of why the instrument reads as too expensive to run.

    The guarantee is not weakened: a discriminator missing from the narrow set
    is looked for across the whole repository before it is called missing, so
    the answer never depends on the guess that a guard's test lives in the same
    crate as the guard.
    """
    if mutations is None:
        return _python_test_names() | _rust_test_names(RUST_CRATES)

    wanted = {t for name, *_ in mutations for t in DISCRIMINATES.get(name, [])}
    # A leading `test_` is pytest's own convention and is what `run_named_only`
    # already uses to route a name to one runner or the other.
    want_python = any(t.startswith("test_") for t in wanted)
    near = {path.split("/")[0] for _, path, _, _ in mutations} & set(RUST_CRATES)

    names = _rust_test_names(sorted(near))
    if want_python:
        names |= _python_test_names()
    if wanted - names:
        names |= _rust_test_names(sorted(set(RUST_CRATES) - near))
        if not want_python:
            names |= _python_test_names()
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
    have = existing_tests(mutations)
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


# Directories a text scan for a test's defining file must not wander into:
# build output, a vendored fork with its own house rules (PATCHES.md governs
# those, not this script), and dependency trees nobody here wrote, which can
# contain a `def` or `fn` with the same name by coincidence.
_SCAN_EXCLUDED_DIRS = {"target", ".git", "vendor", "node_modules", ".venv"}

# A plain definition line, Rust or Python. Good enough to find a name that is
# supposed to be unique in the repository — it does not need to understand
# `#[test]` attributes or decorators, because the guard being measured is
# whether the *file* changed, not whether the match is a test.
_DEF_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)\s*[<(]"
    r"|^\s*(?:async\s+)?def\s+(\w+)\s*\(",
    re.MULTILINE,
)


def _discriminator_source_files(names: set[str]) -> dict[str, set[str]]:
    """Where each of `names` is defined, as repository-relative paths.

    `--changed` used to ask only whether a guard's *anchor* was touched. The
    anchor is product code; the thing that actually proves a guard is
    exercised is the test named for it in `DISCRIMINATES`, and that test can
    be weakened — made to assert less, or to assert something unreachable —
    without the anchor moving at all. That happened: a test was found
    asserting on a target it could never reach, and every `--changed` run
    before it had reported nothing to measure, because the file that had
    changed was the test, not the guard it discriminates.
    So a guard is now selected when either its anchor changed or the file
    defining its named test did, and this is how the second half resolves a
    test name to a file.

    Most of the Rust discriminators are not under `tests/` at all — they are
    `#[test] fn`s inline in the same source file the guard is anchored to
    (`warpgate-protocol-ssh/src/client/mod.rs`, `warpgate-vault/src/client.rs`).
    Only the Python integration tests live under `tests/`. `cargo test -p
    <crate> -- --list` (`_crate_tests`) would answer a related question — where
    a Rust test *runs from* — but that is a module path
    (`client::tests::name`), not a file, and getting it means building that
    crate's test binary. `--changed` runs before anything is known to be worth
    building, so this reads source text instead, the same kind of static check
    `check_anchors` already relies on for the same reason.

    A name with no result is an error, not an empty set. Resolving "no file
    found" to "not touched" would silently reintroduce the exact failure this
    exists to close — a guard reported as having nothing to measure because
    the thing that should have flagged it could not be found.
    """
    found: dict[str, set[str]] = {name: set() for name in names}
    for dirpath, dirnames, filenames in os.walk(REPO):
        dirnames[:] = [d for d in dirnames if d not in _SCAN_EXCLUDED_DIRS]
        for filename in filenames:
            if not filename.endswith((".rs", ".py")):
                continue
            path = Path(dirpath) / filename
            try:
                text = path.read_text()
            except (UnicodeDecodeError, OSError):
                continue
            for match in _DEF_RE.finditer(text):
                name = match.group(1) or match.group(2)
                if name in found:
                    found[name].add(str(path.relative_to(REPO)))

    unresolved = sorted(name for name, files in found.items() if not files)
    if unresolved:
        lines = "\n".join(f"  {name}" for name in unresolved)
        raise SystemExit(
            f"{len(unresolved)} named discriminator(s) could not be resolved "
            f"to a defining file by scanning the repository:\n{lines}\n\n"
            "--changed selects a guard when its test's file changed, the same "
            "way it does when its anchor changes; a test this cannot find a "
            "file for cannot be watched, and reporting it as 'not touched' "
            "would be the silent under-selection this mode exists to avoid."
        )
    return found


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
    # Refused rather than joined. The lock was written unconditionally, so a
    # second run started happily beside a first and both rewrote the same source
    # files — two mutations live at once, and every verdict either produces is
    # about a tree neither of them describes. That happened, and it was noticed
    # only by counting processes.
    #
    # A lock left by a killed run blocks this too, which is the right way round:
    # a stale lock costs one command to clear, and a contaminated sweep costs a
    # number that looks like evidence.
    if LOCK.exists():
        sys.exit(
            f"{LOCK} exists, so a run is in progress or one was killed before it "
            "could clean up.\n"
            "Two runs at once rewrite the same files and neither result means "
            "anything.\n\n"
            "If nothing is running — check with `pgrep -f mutation_matrix` — then "
            "confirm no source was left mutated before clearing it:\n"
            "  python3 -c \"import sys; sys.path.insert(0,'.'); "
            "import tests.mutation_matrix as m; "
            "m.check_anchors(m.MUTATIONS + [m.CANARY])\"\n"
            f"  rm {LOCK}"
        )
    LOCK.write_text("mutation_matrix is rewriting source files in place\n")
    atexit.register(restore_everything)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: sys.exit(130))

    args = sys.argv[1:]
    named_mode = "--named" in args
    args = [a for a in args if a != "--named"]

    fail_fast = "--fail-fast" in args
    args = [a for a in args if a != "--fail-fast"]

    # A full sweep is over fourteen hours on one machine, and a GitHub-hosted
    # job is killed at six. Splitting the guards across jobs is what makes the
    # sweep something CI can actually finish rather than something CI starts.
    # Round-robin rather than contiguous blocks: the integration guards rebuild
    # the gateway and cost minutes each, the unit guards cost seconds, and they
    # are clustered in the table by subject, so contiguous blocks would hand one
    # shard every expensive guard.
    shard = None
    if "--shard" in args:
        at = args.index("--shard")
        if at + 1 >= len(args):
            sys.exit("--shard needs INDEX/TOTAL, e.g. --shard 3/8")
        shard = args[at + 1]
        del args[at : at + 2]
        try:
            shard_index, shard_total = (int(part) for part in shard.split("/", 1))
        except ValueError:
            sys.exit(f"--shard wants INDEX/TOTAL, got {shard!r}")
        if shard_total < 1 or not 1 <= shard_index <= shard_total:
            sys.exit(f"--shard {shard} is out of range: INDEX must be 1..TOTAL")

    changed_base = None
    if "--changed" in args:
        at = args.index("--changed")
        if at + 1 >= len(args):
            sys.exit("--changed needs a base revision to diff against")
        changed_base = args[at + 1]
        del args[at : at + 2]

    only = args[0] if args else ""

    # Skipped in `--named` mode, on Antigravity's ruling (amendment-signed
    # 2026-08-18). This runs the whole `warpgate-vault` suite — 250 seconds,
    # measured — on every invocation, to establish that the tree passes before
    # anything is mutated. `--named` establishes the same thing per guard and
    # more narrowly: the named test must pass *before* the mutation, or the
    # guard is reported `already failing` and no verdict is produced. The
    # precondition is redundant there and load bearing in the other mode.
    if not named_mode:
        rust_unit = run(["cargo", "test", "-p", "warpgate-vault", "-q"])
        if rust_unit.returncode != 0:
            sys.exit("the tree does not pass before mutating; fix that first")

    if changed_base is not None:
        diff = run(["git", "diff", "--name-only", f"{changed_base}...HEAD"])
        if diff.returncode != 0:
            sys.exit(
                f"could not diff against {changed_base!r}. In CI this usually "
                "means the checkout has no history — fetch-depth: 0."
            )
        touched = {line.strip() for line in diff.stdout.splitlines() if line.strip()}
        # A guard's anchor is product code; it is not the only thing that can
        # be touched in a way that invalidates a claim about that guard. The
        # test named for it in DISCRIMINATES can be weakened in a file the
        # anchor never goes near, and the anchor check alone would call that a
        # no-op. So a guard is selected on either signal, not just the first.
        by_anchor = {name for name, path, *_ in MUTATIONS if path in touched}
        wanted_tests = {t for name, *_ in MUTATIONS for t in DISCRIMINATES.get(name, [])}
        discriminator_files = _discriminator_source_files(wanted_tests)
        by_discriminator = {
            name
            for name, *_ in MUTATIONS
            for test in DISCRIMINATES.get(name, [])
            if discriminator_files[test] & touched
        }
        selected = [m for m in MUTATIONS if m[0] in by_anchor or m[0] in by_discriminator]
        print(
            f"{len(touched)} file(s) changed against {changed_base}; "
            f"{len(by_anchor)} guard(s) have an anchor in them, "
            f"{len(by_discriminator - by_anchor)} more have a named "
            f"discriminator test in them "
            f"({len(selected)} of {len(MUTATIONS)} total)"
        )
        # Said out loud rather than left to be inferred from a green check: this
        # mode cannot see a guard broken in a file that changed neither the
        # guard nor the test that is supposed to catch its removal. That is
        # what the full sweep exists for, and a run that reports on a subset
        # has to name the subset.
        if not selected:
            print(
                "no guard's anchor or named discriminator test was touched; "
                "nothing to measure"
            )
            raise SystemExit(0)
    else:
        selected = [m for m in MUTATIONS if not only or only in m[0]]
        if not selected:
            sys.exit(f"no guard matches {only!r}")
    # Each phase says it is starting. Together these can run for over an hour on
    # a full sweep — the discriminator check builds a test binary per crate, and
    # the replacement check runs two workspace-wide `cargo check` passes — and
    # they used to do it in complete silence. A run that cannot be told apart
    # from a hung one gets killed; that happened three times in one day.
    if shard is not None:
        whole = len(selected)
        selected = [m for i, m in enumerate(selected) if i % shard_total == shard_index - 1]
        # Named out loud for the same reason `--changed` names its scope: a
        # shard's green result says nothing about the guards it never held, and
        # only the collected shards add up to a sweep.
        print(
            f"shard {shard}: measuring {len(selected)} of {whole} selected "
            f"guard(s); this shard alone is not a sweep"
        )
        if not selected:
            print("no guard fell into this shard")
            raise SystemExit(0)

    print(f"checking {len(selected)} guard(s) before measuring anything", flush=True)
    print("  anchors...", flush=True)
    check_anchors(selected + [CANARY])
    check_no_duplicate_entries()
    print("  named discriminators exist (builds a test binary per crate)...", flush=True)
    check_discriminators(selected)
    print("  replacements compile (two workspace passes)...", flush=True)
    check_replacements_build(selected + [CANARY], IN_FLIGHT)
    print("  ready\n", flush=True)

    if named_mode:
        # Least-established first. A guard added yesterday is likelier to be
        # wrong than one that has survived a dozen sweeps, and with --fail-fast
        # that is the difference between learning in minutes and learning in
        # hours. Order changes nothing about the verdicts: each guard is
        # measured against its own baseline.
        selected = sorted(selected, key=lambda m: m[0] not in RECENT_GUARDS)
        results = verify_named(selected, fail_fast=fail_fast)
        write_artifact(
            results=results,
            refused=None,
            selected=len(selected),
            mode="named",
            shard=shard,
        )
        good = [r for r in results if r["status"] == "discriminates"]
        print(
            f"\n{len(good)}/{len(results)} guards discriminate: the test named "
            f"after the guard fails when the guard is disabled, and passes when "
            f"it is not"
        )
        # Anything short of all of them fails, including `no discriminating test
        # named`. A guard nothing is pinned to is not a lesser pass — amendment
        # A2 exists because such a guard was reported on for a week while never
        # being disabled once.
        for r in results:
            if r["status"] != "discriminates":
                print(f"  {r['status']}: {r['guard']}")
        raise SystemExit(0 if len(good) == len(results) else 1)

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
        write_artifact(
            results=[], refused=refused, selected=len(selected), shard=shard
        )
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
    write_artifact(
        results=results, refused=None, selected=len(selected), shard=shard
    )

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
