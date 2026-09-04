"""Target authentication with short-lived certificates issued by Vault.

Beyond the happy path, the cases here are drawn from two places: the failures
this feature hit while being built, and the classes of bug Warpgate has actually
shipped before — a credential accepted without proof of possession
(GHSA-3cjp-w4cp-m9c8), a new code path skipping a control every other path
applies (GHSA-qmr2-wp96-h9ff), and an identity taken from the wrong stage of
authentication (GHSA-c94j-vqr5-3mxr).
"""

import json
import time
from pathlib import Path
from uuid import uuid4

import psutil
import pytest
import yaml

from .api_client import admin_client, sdk
from .conftest import TARGET_HOST, ProcessManager, WarpgateProcess
from .stub_vault import (
    SERVICE_ACCOUNT_JWT,
    Recorder,
    StubVault,
    jwt_claims,
    reject_login,
)
from .util import wait_port

USER_PUBLIC_KEY_PATH = Path("ssh-keys/id_ed25519.pub")
USER_PRIVATE_KEY_PATH = "ssh-keys/id_ed25519"


@pytest.fixture(scope="module")
def stub_vault(ctx):
    stub = StubVault(ctx.tmpdir / f"stub-vault-{uuid4()}")
    stub.start()
    yield stub
    stub.stop()


@pytest.fixture(scope="module")
def cert_wg(processes: ProcessManager, ctx, stub_vault: StubVault):
    """Warpgate wired to the stub issuer, with its log kept for assertions."""
    token_path = ctx.tmpdir / f"sa-token-{uuid4()}"
    token_path.write_text(SERVICE_ACCOUNT_JWT)

    log_path = ctx.tmpdir / f"cert-wg-{uuid4()}.log"
    with log_path.open("w") as log:
        wg = processes.start_wg(
            config_patch={
                "vault": {
                    "address": stub_vault.url,
                    "ca_bundle": stub_vault.ca_bundle,
                    "default_role": "warpgate",
                    "auth": {
                        "kind": "kubernetes",
                        "role": "warpgate",
                        "token_path": str(token_path),
                    },
                }
            },
            stdout=log,
            stderr=log,
        )
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        wait_port(wg.ssh_port, for_process=wg.process)
        wg.log_path = log_path
        yield wg


@pytest.fixture(scope="module")
def cert_ssh_port(processes: ProcessManager, stub_vault: StubVault):
    """A target that trusts the stub CA and has no authorized_keys at all."""
    port = processes.start_ssh_server(trusted_ca=[stub_vault.ca_public_key])
    wait_port(port)
    return port


@pytest.fixture(autouse=True)
def reset_stub(stub_vault: StubVault):
    stub_vault.reset()
    yield
    stub_vault.reset()


def make_user_and_target(
    api,
    ssh_port,
    *,
    role=None,
    username="root",
    assign=True,
    allowed_critical_options=None,
):
    wg_role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
    user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
    api.create_public_key_credential(
        user.id,
        sdk.NewPublicKeyCredential(
            label="Public Key",
            openssh_public_key=USER_PUBLIC_KEY_PATH.read_text().strip(),
        ),
    )
    api.add_user_role(user.id, wg_role.id)

    target = api.create_target(
        sdk.TargetDataRequest(
            name=f"cert-{uuid4()}",
            options=sdk.TargetOptions(
                sdk.TargetOptionsTargetSSHOptions(
                    kind="Ssh",
                    host=TARGET_HOST,
                    port=ssh_port,
                    username=username,
                    auth=sdk.SSHTargetAuth(
                        sdk.SSHTargetAuthSshTargetCertificateAuth(
                            kind="Certificate",
                            role=role,
                            allowed_critical_options=[
                                sdk.SshCertificateCriticalOption(name=name, value=value)
                                for name, value in (allowed_critical_options or [])
                            ],
                        )
                    ),
                )
            ),
        )
    )
    if assign:
        api.add_target_role(target.id, wg_role.id)
    return user, target


def start(processes: ProcessManager, wg: WarpgateProcess, user, target, *extra):
    return processes.start_ssh_client(
        f"{user.username}:{target.name}@localhost",
        "-p",
        str(wg.ssh_port),
        "-o",
        f"IdentityFile={USER_PRIVATE_KEY_PATH}",
        "-o",
        "PreferredAuthentications=publickey",
        *extra,
        "ls",
        "/bin/sh",
    )


def connect(processes: ProcessManager, wg: WarpgateProcess, user, target, timeout, *extra):
    client = start(processes, wg, user, target, *extra)
    stdout = client.communicate(timeout=timeout)[0]
    return client.returncode, stdout


def log_since(wg: WarpgateProcess, offset: int) -> str:
    """Only what this test wrote. The gateway is shared by the whole module, so
    searching the whole log would find another test's line just as happily."""
    return Path(wg.log_path).read_text(errors="replace")[offset:]


@pytest.fixture
def api(cert_wg: WarpgateProcess):
    with admin_client(f"https://localhost:{cert_wg.http_port}") as client:
        yield client


class TestHappyPath:
    def test_connects_with_an_issued_certificate(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        user, target = make_user_and_target(api, cert_ssh_port)
        code, stdout = connect(processes, cert_wg, user, target, timeout)

        assert code == 0
        assert stdout == b"/bin/sh\n"
        assert len(stub_vault.signs) == 1
        assert stub_vault.signs[0]["valid_principals"] == "root"
        assert stub_vault.signs[0]["cert_type"] == "user"

    def test_uses_the_default_role_unless_the_target_names_one(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        user, target = make_user_and_target(api, cert_ssh_port)
        connect(processes, cert_wg, user, target, timeout)
        assert stub_vault.signs[-1]["role"] == "warpgate"

        user, target = make_user_and_target(api, cert_ssh_port, role="privileged")
        connect(processes, cert_wg, user, target, timeout)
        assert stub_vault.signs[-1]["role"] == "privileged"

    def test_each_session_gets_a_fresh_key_and_certificate(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        user, target = make_user_and_target(api, cert_ssh_port)
        for _ in range(3):
            assert connect(processes, cert_wg, user, target, timeout)[0] == 0

        offered = [sign["public_key"] for sign in stub_vault.signs]
        assert len(offered) == 3
        assert len(set(offered)) == 3, "an ephemeral key was reused between sessions"

    def test_the_token_is_reused_across_sessions(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        user, target = make_user_and_target(api, cert_ssh_port)
        for _ in range(3):
            connect(processes, cert_wg, user, target, timeout)

        # The first session may find a token cached by an earlier test, so the
        # assertion is that three sessions do not each cause a login.
        assert len(stub_vault.logins) <= 1

    def test_no_ttl_is_requested_unless_one_is_configured(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """Vault reads an absent `ttl` as the role's default. Sending a zero
        instead would ask for the shortest certificate Vault will issue."""
        user, target = make_user_and_target(api, cert_ssh_port)
        connect(processes, cert_wg, user, target, timeout)

        assert "ttl" not in stub_vault.signs[-1]

    def test_a_configured_ttl_is_asked_for(
        self, processes: ProcessManager, ctx, stub_vault, cert_ssh_port, timeout
    ):
        """The TTL can be held down from Warpgate's side without editing the
        Vault role — Vault clamps it to the role's `max_ttl` regardless."""
        token_path = ctx.tmpdir / f"sa-token-{uuid4()}"
        token_path.write_text(SERVICE_ACCOUNT_JWT)

        wg = processes.start_wg(
            config_patch={
                "vault": {
                    "address": stub_vault.url,
                    "ca_bundle": stub_vault.ca_bundle,
                    "default_role": "warpgate",
                    "certificate_ttl": "90s",
                    "auth": {
                        "kind": "kubernetes",
                        "role": "warpgate",
                        "token_path": str(token_path),
                    },
                }
            }
        )
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        wait_port(wg.ssh_port, for_process=wg.process)

        with admin_client(f"https://localhost:{wg.http_port}") as api:
            user, target = make_user_and_target(api, cert_ssh_port)

        assert connect(processes, wg, user, target, timeout)[0] == 0
        assert stub_vault.signs[-1]["ttl"] == "90s"


class TestIdentity:
    """The certificate must name the user Warpgate actually authenticated."""

    def test_key_id_carries_the_authenticated_user_and_session(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        user, target = make_user_and_target(api, cert_ssh_port)
        connect(processes, cert_wg, user, target, timeout)

        key_id = stub_vault.signs[-1]["key_id"]
        prefix, username, session = key_id.split(":")
        assert prefix == "warpgate"
        assert username == user.username
        assert session

    def test_the_target_username_is_not_the_warpgate_username(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """`valid_principals` bounds access on the target and must never be
        taken from the identity the client chose to log into Warpgate with."""
        user, target = make_user_and_target(api, cert_ssh_port)
        connect(processes, cert_wg, user, target, timeout)

        assert stub_vault.signs[-1]["valid_principals"] == "root"
        assert user.username not in stub_vault.signs[-1]["valid_principals"]

    def test_a_comma_in_the_target_username_is_refused(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """Vault reads `valid_principals` as a comma-separated list, so a comma
        in the target's username would ask for a certificate good for accounts
        nobody named. No request may leave at all."""
        user, target = make_user_and_target(api, cert_ssh_port, username="deploy,root")
        assert connect(processes, cert_wg, user, target, timeout)[0] != 0

        assert stub_vault.signs == []

    def test_a_newline_in_the_target_username_never_reaches_vault(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """The principal is written into the certificate and the certificate is
        written into the target's sshd log, so a newline in a target's username
        is a way to compose log lines on the target. Nothing may be sent at all
        — not even the login that would precede it."""
        user, target = make_user_and_target(api, cert_ssh_port, username="root\nnobody")
        assert connect(processes, cert_wg, user, target, timeout)[0] != 0

        assert stub_vault.requests == []

    def test_a_ticket_session_is_named_after_its_user_and_not_its_secret(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """The key ID must name the user Warpgate authenticated, however it
        authenticated them. A ticket session logs in as `ticket-<secret>`, so a
        key ID taken from the login name rather than from the authentication
        result would name nobody and copy the ticket secret into the target's
        sshd log — the shape of GHSA-c94j-vqr5-3mxr."""
        user, target = make_user_and_target(api, cert_ssh_port)
        secret = api.create_ticket(
            sdk.CreateTicketRequest(target_name=target.name, username=user.username)
        ).secret

        client = processes.start_ssh_client(
            f"ticket-{secret}@localhost",
            "-p",
            str(cert_wg.ssh_port),
            "-o",
            "PreferredAuthentications=password",
            "-i",
            "/dev/null",
            "ls",
            "/bin/sh",
            password="irrelevant",
        )
        assert client.communicate(timeout=timeout)[0] == b"/bin/sh\n"

        key_id = stub_vault.signs[-1]["key_id"]
        assert key_id.startswith(f"warpgate:{user.username}:")
        assert secret not in key_id


class TestRejections:
    def test_target_that_does_not_trust_the_ca(
        self, processes, cert_wg, stub_vault, api, timeout
    ):
        port = processes.start_ssh_server()
        wait_port(port)

        user, target = make_user_and_target(api, port)
        code, stdout = connect(processes, cert_wg, user, target, timeout)

        assert code != 0
        assert stdout == b""
        assert len(stub_vault.signs) == 1, "the target rejected it, not Warpgate"

    def test_expired_certificate(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """Warpgate refuses it before offering it, and says so.

        A non-zero exit code proves nothing here: the target's own sshd refuses
        an expired certificate whether or not Warpgate looked. Deleting the
        expiry check would leave this test passing for the target's reasons, so
        it asserts on the one message only that check produces.
        """
        offset = Path(cert_wg.log_path).stat().st_size
        stub_vault.validity = "-2h:-1h"
        user, target = make_user_and_target(api, cert_ssh_port)
        assert connect(processes, cert_wg, user, target, timeout)[0] != 0
        assert len(stub_vault.signs) == 1
        assert "already expired" in log_since(cert_wg, offset)

    def test_certificate_that_is_not_yet_valid(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """A target whose clock lags far enough behind Warpgate's sees this.

        Warpgate has no `valid_after` check of its own — the refusal is entirely
        the target's — so what is asserted is Warpgate's contribution: the
        window it reports and the hint naming the clock. Without that, whoever
        is debugging goes looking at credentials that are fine.
        """
        offset = Path(cert_wg.log_path).stat().st_size
        stub_vault.validity = "+1h:+2h"
        user, target = make_user_and_target(api, cert_ssh_port)
        assert connect(processes, cert_wg, user, target, timeout)[0] != 0
        assert len(stub_vault.signs) == 1
        assert "check the target's clock" in log_since(cert_wg, offset)

    def test_certificate_for_a_different_principal(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """The target would refuse an account it does not have, so a failed
        connection says nothing about the principal check. This asserts the
        refusal Warpgate itself produces, before anything is offered."""
        offset = Path(cert_wg.log_path).stat().st_size
        stub_vault.principals = "nobody"
        user, target = make_user_and_target(api, cert_ssh_port)
        assert connect(processes, cert_wg, user, target, timeout)[0] != 0
        assert len(stub_vault.signs) == 1
        assert "rather than only the target account" in log_since(cert_wg, offset)

    def test_certificate_issued_for_a_key_warpgate_does_not_hold(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """A certificate is a public credential. Signing someone else's key must
        not authenticate anyone — the class of bug behind GHSA-3cjp-w4cp-m9c8,
        where an SSH key offer was accepted without a signature."""
        offset = Path(cert_wg.log_path).stat().st_size
        stub_vault.sign_public_key = stub_vault.unrelated_public_key()
        user, target = make_user_and_target(api, cert_ssh_port)
        assert connect(processes, cert_wg, user, target, timeout)[0] != 0
        assert len(stub_vault.signs) == 1
        # The target would refuse it too, but then the log would say only that
        # the target said no. Warpgate knows which key it generated.
        assert "signed a key other than" in log_since(cert_wg, offset)

    def test_a_host_certificate_is_not_offered_to_the_target(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """A host certificate can never authenticate a user, so an issuer that
        returns one is misconfigured or lying. Either way the reason belongs in
        Warpgate's log rather than arriving as an unexplained rejection."""
        offset = Path(cert_wg.log_path).stat().st_size
        stub_vault.cert_type = "host"
        user, target = make_user_and_target(api, cert_ssh_port)
        assert connect(processes, cert_wg, user, target, timeout)[0] != 0
        assert len(stub_vault.signs) == 1
        assert "host certificate" in log_since(cert_wg, offset)

    def test_malformed_certificate(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        stub_vault.signed_key = "this is not a certificate"
        user, target = make_user_and_target(api, cert_ssh_port)
        assert connect(processes, cert_wg, user, target, timeout)[0] != 0
        assert len(stub_vault.signs) == 1

    @pytest.mark.parametrize(
        "data",
        [
            pytest.param({}, id="no-signed-key"),
            pytest.param({"signed_key": ""}, id="empty-signed-key"),
            pytest.param({"signed_key": 42}, id="signed-key-is-not-a-string"),
        ],
    )
    def test_a_success_that_carries_no_certificate(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout, data
    ):
        """`200 OK` is not a certificate. Each of these parses as JSON and none
        of them is a credential, so the session has to end rather than continue
        with whatever an absent field defaults to."""
        stub_vault.sign_data = data
        user, target = make_user_and_target(api, cert_ssh_port)
        assert connect(processes, cert_wg, user, target, timeout)[0] != 0
        assert len(stub_vault.signs) == 1

    def test_an_unexpected_forced_command_is_refused(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """The target's sshd enforces critical options, so an issuer that
        attaches `force-command` decides what the session runs — under the
        user's own principal and key ID, which makes the target's log attribute
        the issuer's command to them. Planting one needs only write access to a
        Vault role, not the right to sign or a route to the target, so Warpgate
        is the only place this can be caught."""
        stub_vault.sign_options = ["force-command=echo chosen-by-the-issuer"]
        user, target = make_user_and_target(api, cert_ssh_port)
        code, stdout = connect(processes, cert_wg, user, target, timeout)

        assert code != 0
        assert b"chosen-by-the-issuer" not in stdout, "the forced command ran"
        assert stub_vault.signs, "no certificate was issued, so nothing was refused"

    def test_the_refusal_reaches_the_user_not_only_the_log(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """A server-side warning nobody is watching is not a control. Whoever is
        connecting has to be told, and told that it was Warpgate that refused —
        "the target rejected you" sends them to the wrong machine."""
        stub_vault.sign_options = ["force-command=echo chosen-by-the-issuer"]
        user, target = make_user_and_target(api, cert_ssh_port)

        client = start(processes, cert_wg, user, target, "-tt")
        stdout = client.communicate(timeout=timeout)[0].decode(errors="replace")

        assert "Warpgate refused the certificate" in stdout
        assert "force-command" in stdout

    def test_a_critical_option_the_target_expects_is_allowed_through(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """A restricted Vault role may set `default_critical_options` on
        purpose. Naming it on the target is how an operator says so."""
        stub_vault.sign_options = ["force-command=echo expected-by-the-operator"]
        user, target = make_user_and_target(
            api,
            cert_ssh_port,
            allowed_critical_options=[
                ("force-command", "echo expected-by-the-operator")
            ],
        )
        code, stdout = connect(processes, cert_wg, user, target, timeout)

        assert (code, stdout) == (0, b"expected-by-the-operator\n")

    def test_a_pinned_value_must_match(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """Allowing the name alone would let the issuer choose the command; the
        point of pinning is that the value is the part that matters."""
        stub_vault.sign_options = ["force-command=echo something-else-entirely"]
        user, target = make_user_and_target(
            api,
            cert_ssh_port,
            allowed_critical_options=[("force-command", "echo the-expected-one")],
        )
        code, stdout = connect(processes, cert_wg, user, target, timeout)

        assert code != 0
        assert b"something-else-entirely" not in stdout

    def test_a_certificate_naming_the_wrong_account_is_refused(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """Vault returns the requested principals verbatim or refuses, so a set
        that omits the account being reached did not come from this request.

        The target's sshd would refuse this certificate too, which is exactly
        why the assertion is on who did the refusing: without Warpgate's own
        check the session still fails, just with the wrong explanation and
        after the certificate has been put on the wire.
        """
        stub_vault.principals = "someone-else"
        user, target = make_user_and_target(api, cert_ssh_port)

        client = start(processes, cert_wg, user, target, "-tt")
        stdout = client.communicate(timeout=timeout)[0].decode(errors="replace")

        assert client.returncode != 0
        assert stub_vault.signs, "no certificate was issued, so nothing was refused"
        assert "Warpgate refused the certificate" in stdout
        assert "rather than only the target account root" in stdout


class TestIssuerFailures:
    def test_issuer_refuses_to_sign(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        stub_vault.sign_status = 403
        user, target = make_user_and_target(api, cert_ssh_port)
        assert connect(processes, cert_wg, user, target, timeout)[0] != 0
        # Without this the test passes just as well when the certificate
        # path never ran at all.
        assert stub_vault.signs, "no certificate was ever requested"

    def test_a_persistent_denial_is_not_retried_forever(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """One re-login distinguishes a stale token from a policy denial. A
        second failure has to be final, or a denied target becomes a request
        amplifier against Vault."""
        stub_vault.sign_status = 403
        user, target = make_user_and_target(api, cert_ssh_port)
        connect(processes, cert_wg, user, target, timeout)

        assert len(stub_vault.signs) == 2

    def test_a_stale_token_is_refreshed_once(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """Vault can reject a token long before its lease runs out — after a
        restart, or a revocation. Warpgate must recover within the session
        rather than failing until the lease expires."""
        user, target = make_user_and_target(api, cert_ssh_port)
        assert connect(processes, cert_wg, user, target, timeout)[0] == 0

        stub_vault.invalidate_token()
        assert connect(processes, cert_wg, user, target, timeout)[0] == 0
        assert len(stub_vault.signs) == 3, "expected one rejected and one retried sign"

    def test_a_redirect_from_the_issuer_is_refused(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """Following a redirect would hand `X-Vault-Token` to whatever host it
        names — reqwest only knows to strip `Authorization`. The session must
        fail instead, and the redirect target must never be contacted."""
        recorder = Recorder()
        recorder.start()
        try:
            stub_vault.sign_redirect_to = f"{recorder.url}/v1/steal"
            user, target = make_user_and_target(api, cert_ssh_port)

            assert connect(processes, cert_wg, user, target, timeout)[0] != 0
            assert stub_vault.signs, "the signing request was never made"
            assert recorder.requests == [], "the redirect was followed"
        finally:
            recorder.stop()

    def test_an_oversized_error_body_is_not_relayed_to_the_client(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """An endpoint answering on the Vault address can return any body it
        likes. It must neither be buffered whole nor shown to the user."""
        marker = "SENSITIVE-INTERNAL-DETAIL"
        stub_vault.sign_error_body = (marker + "x" * 64).encode() * 200_000

        user, target = make_user_and_target(api, cert_ssh_port)
        # With a PTY, or the central assertion is unfalsifiable: without a PTY
        # channel `emit_pty_output` has nothing to write to, so *no* connection
        # error reaches the client and "the marker is absent" holds however
        # badly the body is handled. The sanitiser could be removed entirely and
        # this would still pass.
        client = start(processes, cert_wg, user, target, "-tt")
        shown = client.communicate(timeout=timeout)[0].decode(errors="replace")

        assert stub_vault.signs, "the signing request was never made"
        assert client.returncode != 0
        # Something was shown, and it was not the issuer's own words.
        assert "Vault" in shown or "certificate" in shown.lower(), (
            f"no failure reached the client at all: {shown[:200]!r}"
        )
        assert marker not in shown

    def test_an_oversized_signing_response_is_not_buffered_whole(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """The failed-response path was bounded; the successful one is the same
        body with a different status code on it, and it is parsed once per
        session. Left unbounded it is memory the issuer gets to allocate inside
        Warpgate, as often as sessions are started."""
        user, target = make_user_and_target(api, cert_ssh_port)
        assert connect(processes, cert_wg, user, target, timeout)[0] == 0

        gateway = psutil.Process(cert_wg.process.pid)
        before = gateway.memory_info().rss
        stub_vault.signed_key = "ssh-ed25519-cert-v01@openssh.com " + "A" * 100_000_000
        assert connect(processes, cert_wg, user, target, timeout * 3)[0] != 0
        growth = gateway.memory_info().rss - before

        assert growth < 50_000_000, f"the body was buffered whole ({growth / 1e6:.0f} MB)"

        # And the gateway is still there, with the memory it started with.
        stub_vault.signed_key = None
        assert connect(processes, cert_wg, user, target, timeout)[0] == 0

    def test_a_revoked_token_costs_one_login_no_matter_how_many_sessions_find_it(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """A Vault restart is discovered by every session in flight at the same
        moment. If each answered by logging in, ordinary traffic would meet the
        restart with a login per session — and each of those with a credential
        read off disk."""
        user, target = make_user_and_target(api, cert_ssh_port)
        assert connect(processes, cert_wg, user, target, timeout)[0] == 0

        stub_vault.invalidate_token()
        # Wide enough that the sessions are genuinely inside the same login,
        # rather than politely arriving one after another.
        stub_vault.login_delay = 1
        logins = len(stub_vault.logins)

        clients = [start(processes, cert_wg, user, target) for _ in range(6)]
        for client in clients:
            client.communicate(timeout=timeout * 3)

        assert [client.returncode for client in clients] == [0] * 6
        assert len(stub_vault.logins) - logins == 1

    def test_the_client_is_never_shown_the_issuers_own_words(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """What the user sees comes from a fixed list; the issuer's body is
        written for operators and names mounts, policies and hosts. This asks
        for a PTY on purpose — without one the message has nowhere to go and the
        check would pass without anything being shown at all."""
        stub_vault.sign_error_body = b"1 error occurred: permission denied by policy ssh-signer-7"
        user, target = make_user_and_target(api, cert_ssh_port)
        code, stdout = connect(processes, cert_wg, user, target, timeout, "-tt")

        assert code != 0
        shown = stdout.decode(errors="replace")
        assert "Vault service error" in shown, "the failure never reached the user"
        assert "ssh-signer-7" not in shown
        assert "policy" not in shown

        # Without this the test passes just as well when the certificate path
        # never ran at all.
        assert stub_vault.signs, "no certificate was ever requested"

    def test_an_error_body_split_mid_character_does_not_kill_the_session(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """Truncating at a fixed byte count lands inside a multi-byte character
        for some bodies; slicing a Rust `String` there panics."""
        offset = Path(cert_wg.log_path).stat().st_size
        stub_vault.sign_error_body = b"a" * 255 + "é".encode() + b"b" * 64

        user, target = make_user_and_target(api, cert_ssh_port)
        assert connect(processes, cert_wg, user, target, timeout)[0] != 0
        # Without this the test passes just as well when the certificate path
        # never ran at all.
        assert stub_vault.signs, "no certificate was ever requested"

        # Everything above is satisfied whether or not the truncation is safe:
        # the stub's 500 already fails the session, and `tokio::sync::Mutex` does
        # not poison, so the next login succeeds even if a task panicked.
        #
        # Measured with the guard removed: the panic takes the signing task down
        # and the client hangs until its own timeout, so what discriminates in
        # practice is the first `connect` never returning. This assertion is the
        # faster and more legible signal for the case where a panic does not
        # hang — it is not the one that fires today, and saying so is cheaper
        # than someone later assuming it is.
        assert "panicked at" not in log_since(cert_wg, offset), (
            "slicing the body at a byte boundary panicked the signing task"
        )

        # The gateway has to still be there afterwards.
        stub_vault.sign_error_body = None
        assert connect(processes, cert_wg, user, target, timeout)[0] == 0

    def test_issuer_unreachable_fails_promptly(
        self, processes: ProcessManager, ctx, cert_ssh_port, timeout
    ):
        """An unreachable Vault must fail the session rather than stall it, so
        an issuer outage looks like an auth failure and not a hang."""
        dead = StubVault(ctx.tmpdir / f"dead-vault-{uuid4()}")
        dead.start()
        address = dead.url
        dead.stop()

        token_path = ctx.tmpdir / f"sa-token-{uuid4()}"
        token_path.write_text(SERVICE_ACCOUNT_JWT)

        wg = processes.start_wg(
            config_patch={
                "vault": {
                    "address": address,
                    "default_role": "warpgate",
                    "timeout": "5s",
                    "auth": {
                        "kind": "kubernetes",
                        "role": "warpgate",
                        "token_path": str(token_path),
                    },
                }
            }
        )
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        wait_port(wg.ssh_port, for_process=wg.process)

        with admin_client(f"https://localhost:{wg.http_port}") as api:
            user, target = make_user_and_target(api, cert_ssh_port)

        # The assertion is the absence of a timeout: communicate() raises if the
        # session is still open when the test's own deadline passes.
        code, _ = connect(processes, wg, user, target, timeout)
        assert code != 0


class TestAuthMethods:
    def test_kubernetes_sends_the_service_account_token(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        user, target = make_user_and_target(api, cert_ssh_port)
        connect(processes, cert_wg, user, target, timeout)

        # An earlier test may have left a usable token cached, so force a login.
        stub_vault.invalidate_token()
        connect(processes, cert_wg, user, target, timeout)

        login = stub_vault.logins[-1]
        assert login["method"] == "kubernetes"
        assert login["role"] == "warpgate"
        assert login["jwt"] == SERVICE_ACCOUNT_JWT

    def test_approle_sends_the_secret_id_from_its_file(
        self, processes: ProcessManager, ctx, stub_vault, cert_ssh_port, timeout
    ):
        """The secret ID is read from disk rather than the config so it can be
        rotated underneath a running Warpgate."""
        secret_id_path = ctx.tmpdir / f"secret-id-{uuid4()}"
        secret_id_path.write_text("stub-secret-id\n")

        wg = processes.start_wg(
            config_patch={
                "vault": {
                    "address": stub_vault.url,
                    "ca_bundle": stub_vault.ca_bundle,
                    "default_role": "warpgate",
                    "auth": {
                        "kind": "app_role",
                        "role_id": "stub-role-id",
                        "secret_id_path": str(secret_id_path),
                    },
                }
            }
        )
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        wait_port(wg.ssh_port, for_process=wg.process)

        with admin_client(f"https://localhost:{wg.http_port}") as api:
            user, target = make_user_and_target(api, cert_ssh_port)

        assert connect(processes, wg, user, target, timeout)[0] == 0

        login = stub_vault.logins[-1]
        assert login["method"] == "approle"
        assert login["role_id"] == "stub-role-id"
        assert login["secret_id"] == "stub-secret-id"


class TestCloudAuthMethods:
    """The cloud methods take their credential from a metadata service, so
    nothing durable is written to the host at all. Only the request Warpgate
    builds is under test here; the metadata services themselves need a real VM."""

    def _wg_with_auth(self, processes, stub_vault, auth, env=None):
        wg = processes.start_wg(
            config_patch={
                "vault": {
                    "address": stub_vault.url,
                    "ca_bundle": stub_vault.ca_bundle,
                    "default_role": "warpgate",
                    "auth": auth,
                }
            },
            env=env,
        )
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        wait_port(wg.ssh_port, for_process=wg.process)
        return wg

    def test_azure_sends_imds_token_and_vm_coordinates(
        self, processes: ProcessManager, stub_vault, cert_ssh_port, timeout
    ):
        wg = self._wg_with_auth(
            processes,
            stub_vault,
            {
                "kind": "azure",
                "role": "warpgate",
                "metadata_address": stub_vault.metadata_url,
            },
        )
        with admin_client(f"https://localhost:{wg.http_port}") as api:
            user, target = make_user_and_target(api, cert_ssh_port)

        assert connect(processes, wg, user, target, timeout)[0] == 0

        login = stub_vault.logins[-1]
        assert login["method"] == "azure"
        assert jwt_claims(login["jwt"])["aud"] == "https://management.azure.com/"
        assert login["subscription_id"] == "sub-1"
        assert login["resource_group_name"] == "rg-1"
        assert login["vm_name"] == "vm-1"
        assert any("management.azure.com" in r for r in stub_vault.metadata_requests)

    def test_gcp_requests_a_token_bound_to_its_role(
        self, processes: ProcessManager, stub_vault, cert_ssh_port, timeout
    ):
        """The audience ties the token to one Vault role, so a token minted for
        another role cannot be presented here."""
        wg = self._wg_with_auth(
            processes,
            stub_vault,
            {
                "kind": "gcp",
                "role": "warpgate",
                "metadata_address": stub_vault.metadata_url,
            },
        )
        with admin_client(f"https://localhost:{wg.http_port}") as api:
            user, target = make_user_and_target(api, cert_ssh_port)

        assert connect(processes, wg, user, target, timeout)[0] == 0

        login = stub_vault.logins[-1]
        assert login["method"] == "gcp"
        assert jwt_claims(login["jwt"])["aud"] == "vault/warpgate"
        assert any(
            "audience=vault%2Fwarpgate" in r for r in stub_vault.metadata_requests
        )

    def test_aws_signs_the_global_endpoint_by_default(
        self, processes: ProcessManager, stub_vault, cert_ssh_port, timeout
    ):
        """Vault replays the request against the global STS endpoint, which only
        accepts signatures scoped to us-east-1. Signing a regional endpoint by
        default makes every login fail with SignatureDoesNotMatch."""
        from base64 import b64decode

        wg = self._wg_with_auth(
            processes,
            stub_vault,
            {"kind": "aws", "role": "warpgate"},
            env={
                "AWS_ACCESS_KEY_ID": "ASIA0000000000000000",
                "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "AWS_SESSION_TOKEN": "AQoDYXdzEJr1KEXAMPLEtoken",
            },

        )
        with admin_client(f"https://localhost:{wg.http_port}") as api:
            user, target = make_user_and_target(api, cert_ssh_port)

        connect(processes, wg, user, target, timeout)

        login = stub_vault.logins[-1]
        assert b64decode(login["iam_request_url"]) == b"https://sts.amazonaws.com/"

        headers = json.loads(b64decode(login["iam_request_headers"]))
        authorization = next(
            value for name, value in headers.items() if name.lower() == "authorization"
        )
        assert "/us-east-1/sts/aws4_request" in authorization

    def test_aws_sends_a_signed_sts_request(
        self, processes: ProcessManager, stub_vault, cert_ssh_port, timeout
    ):
        """Vault replays the signed request against STS, so the signature — not a
        disclosed credential — is what proves identity."""
        from base64 import b64decode

        wg = self._wg_with_auth(
            processes,
            stub_vault,
            {
                "kind": "aws",
                "role": "warpgate",
                "region": "us-east-1",
                "server_id": "vault.example.com",
            },
            # Supplied here rather than inherited, so the test does not depend on
            # whatever credentials the developer happens to have. The signature is
            # verified for shape, never sent to AWS.
            env={
                "AWS_ACCESS_KEY_ID": "ASIA0000000000000000",
                "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "AWS_SESSION_TOKEN": "AQoDYXdzEJr1KEXAMPLEtoken",
            },

        )
        with admin_client(f"https://localhost:{wg.http_port}") as api:
            user, target = make_user_and_target(api, cert_ssh_port)

        connect(processes, wg, user, target, timeout)

        login = stub_vault.logins[-1]
        assert login["method"] == "aws"
        assert login["iam_http_request_method"] == "POST"
        assert b64decode(login["iam_request_url"]) == b"https://sts.us-east-1.amazonaws.com/"
        assert b64decode(login["iam_request_body"]) == (
            b"Action=GetCallerIdentity&Version=2011-06-15"
        )

        headers = json.loads(b64decode(login["iam_request_headers"]))
        headers = {name.lower(): value for name, value in headers.items()}
        assert headers["x-vault-aws-iam-server-id"] == "vault.example.com"
        assert "AWS4-HMAC-SHA256" in headers["authorization"]
        assert "x-vault-aws-iam-server-id" in headers["authorization"], (
            "the server ID must be signed, not merely sent"
        )

    def test_approle_response_wrapping(
        self, processes, cert_ssh_port, stub_vault, ctx, timeout
    ):
        secret_id_path = ctx.tmpdir / f"wrapping-token-{uuid4()}"
        secret_id_path.write_text("unwrap:stub-wrapping-token")

        wg = self._wg_with_auth(
            processes,
            stub_vault,
            {
                "kind": "app_role",
                "role_id": "role-1",
                "secret_id_path": str(secret_id_path),
            },
        )
        with admin_client(f"https://localhost:{wg.http_port}") as api:
            user, target = make_user_and_target(api, cert_ssh_port)

        assert connect(processes, wg, user, target, timeout)[0] == 0

        login = stub_vault.logins[-1]
        assert login["method"] == "approle"
        assert login["secret_id"] == "unwrapped-secret-id"

    def test_a_wrapping_token_is_redeemed_once_and_the_secret_id_reused(
        self, processes, cert_ssh_port, stub_vault, ctx, timeout
    ):
        """A wrapping token can be redeemed exactly once, while the secret ID
        inside it stays usable. Unwrapping per login would leave every session
        after the first unable to authenticate to Vault at all."""
        secret_id_path = ctx.tmpdir / f"wrapping-token-{uuid4()}"
        secret_id_path.write_text("unwrap:stub-wrapping-token")

        wg = self._wg_with_auth(
            processes,
            stub_vault,
            {
                "kind": "app_role",
                "role_id": "role-1",
                "secret_id_path": str(secret_id_path),
            },
        )
        with admin_client(f"https://localhost:{wg.http_port}") as api:
            user, target = make_user_and_target(api, cert_ssh_port)

        assert connect(processes, wg, user, target, timeout)[0] == 0

        # Forces a second login rather than waiting out the lease.
        stub_vault.invalidate_token()
        assert connect(processes, wg, user, target, timeout)[0] == 0

        assert len(stub_vault.logins) == 2, "the second session did not log in again"
        assert stub_vault.logins[-1]["secret_id"] == "unwrapped-secret-id"
        assert len(stub_vault.unwraps) == 1, "the wrapping token was redeemed twice"

    def test_a_freshly_provisioned_wrapping_token_is_picked_up(
        self, processes, cert_ssh_port, stub_vault, ctx, timeout
    ):
        """Caching the unwrapped secret ID must not mean ignoring the file: an
        operator rotating the credential writes a new wrapping token there."""
        secret_id_path = ctx.tmpdir / f"wrapping-token-{uuid4()}"
        secret_id_path.write_text("unwrap:first-wrapping-token")

        wg = self._wg_with_auth(
            processes,
            stub_vault,
            {
                "kind": "app_role",
                "role_id": "role-1",
                "secret_id_path": str(secret_id_path),
            },
        )
        with admin_client(f"https://localhost:{wg.http_port}") as api:
            user, target = make_user_and_target(api, cert_ssh_port)

        assert connect(processes, wg, user, target, timeout)[0] == 0

        secret_id_path.write_text("unwrap:second-wrapping-token")
        stub_vault.invalidate_token()
        assert connect(processes, wg, user, target, timeout)[0] == 0

        assert stub_vault.unwraps == ["first-wrapping-token", "second-wrapping-token"]


class TestConfigReload:
    def test_a_new_vault_address_takes_effect_without_a_restart(
        self, processes: ProcessManager, ctx, stub_vault, cert_ssh_port, timeout
    ):
        """Every other section of the config is watched and applied live. A
        `vault:` that quietly needed a restart would be the one exception, and
        an operator editing it would have no way of knowing."""
        token_path = ctx.tmpdir / f"sa-token-{uuid4()}"
        token_path.write_text(SERVICE_ACCOUNT_JWT)

        second = StubVault(ctx.tmpdir / f"stub-vault-reload-{uuid4()}")
        second.start()
        try:
            port = processes.start_ssh_server(trusted_ca=[second.ca_public_key])
            wait_port(port)

            wg = processes.start_wg(
                config_patch={
                    "vault": {
                        "address": stub_vault.url,
                        "ca_bundle": stub_vault.ca_bundle,
                        "default_role": "warpgate",
                        "auth": {
                            "kind": "kubernetes",
                            "role": "warpgate",
                            "token_path": str(token_path),
                        },
                    }
                }
            )
            wait_port(wg.http_port, for_process=wg.process, recv=False)
            wait_port(wg.ssh_port, for_process=wg.process)

            with admin_client(f"https://localhost:{wg.http_port}") as api:
                user, target = make_user_and_target(api, port)

            # The running config points at the first issuer, whose CA this
            # target does not trust — so this must fail before the edit.
            assert connect(processes, wg, user, target, timeout)[0] != 0

            config = yaml.safe_load(wg.config_path.read_text())
            config["vault"]["address"] = second.url
            config["vault"]["ca_bundle"] = second.ca_bundle
            wg.config_path.write_text(yaml.dump(config))

            # The watcher debounces for 500ms before reloading once.
            deadline = time.time() + 20
            while time.time() < deadline:
                if second.signs:
                    break
                connect(processes, wg, user, target, timeout)
                time.sleep(1)

            assert second.signs, "the edited Vault address was never picked up"
            assert connect(processes, wg, user, target, timeout)[0] == 0
        finally:
            second.stop()


class TestTheHostKeyCheck:
    """The admin host-key check reaches the same connection code the SSH path
    does. It asks for one thing — the target's host key — and must not carry on
    into authentication behind the operator's back."""

    def test_checking_a_host_key_issues_no_certificate(
        self, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """Pressing the button on a certificate target would otherwise mint a
        real certificate and open a real authenticated session that nothing is
        attached to, holding until the inactivity timeout."""
        _, target = make_user_and_target(api, cert_ssh_port)

        first = api.check_ssh_host_key(sdk.CheckSshHostKeyRequest(target_id=target.id))
        assert first.remote_key_base64, "the check did not reach the target at all"

        # The first press leaves the key trusted; it is every press after that
        # one which used to run on into authentication.
        api.check_ssh_host_key(sdk.CheckSshHostKeyRequest(target_id=target.id))
        api.check_ssh_host_key(sdk.CheckSshHostKeyRequest(target_id=target.id))

        # The request returns as soon as the key arrives; a connection that kept
        # going would reach the issuer a moment afterwards, so the assertion has
        # to outlast the response rather than race it.
        deadline = time.time() + 5
        while time.time() < deadline:
            assert stub_vault.signs == [], "the host key check issued a certificate"
            time.sleep(0.25)

    def test_the_check_leaves_no_session_behind(
        self, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """A session opened by the check is invisible in the UI and outlives the
        request, so counting what the gateway is still holding is the only way
        to see it."""
        _, target = make_user_and_target(api, cert_ssh_port)
        api.check_ssh_host_key(sdk.CheckSshHostKeyRequest(target_id=target.id))

        # Measured as a delta: the gateway is shared by the whole module, so
        # earlier tests have left sessions and sockets of their own behind.
        gateway = psutil.Process(cert_wg.process.pid)
        target_socket_count = lambda: len(
            [c for c in gateway.net_connections(kind="tcp") if c.raddr and c.raddr.port == cert_ssh_port]
        )
        before_sockets = target_socket_count()
        before_sessions = api.get_sessions().total

        for _ in range(3):
            api.check_ssh_host_key(sdk.CheckSshHostKeyRequest(target_id=target.id))

        assert api.get_sessions().total == before_sessions, "the check registered a session"
        # A connection still open to the target is the observable trace of a
        # client task that never exited. One-sided on purpose: an earlier test's
        # socket finishing its close during this window lowers the count, and
        # that is not what is under test.
        assert target_socket_count() <= before_sockets


class TestTheStubItself:
    """The auth-method tests only mean something if the stub would have noticed a
    wrong payload. These check the checker, without starting anything."""

    def _aws_payload(self, **overrides):
        from base64 import b64encode

        payload = {
            "iam_http_request_method": "POST",
            "iam_request_url": b64encode(b"https://sts.amazonaws.com/").decode(),
            "iam_request_body": b64encode(
                b"Action=GetCallerIdentity&Version=2011-06-15"
            ).decode(),
            "iam_request_headers": b64encode(
                json.dumps({"authorization": "AWS4-HMAC-SHA256 Credential=..."}).encode()
            ).decode(),
        }
        payload.update(overrides)
        return payload

    def test_a_well_formed_aws_payload_is_accepted(self):
        assert reject_login("aws", self._aws_payload()) is None

    @pytest.mark.parametrize(
        "overrides",
        [
            {"iam_http_request_method": "GET"},
            {"iam_request_url": "aHR0cHM6Ly9ldmlsLmV4YW1wbGUuY29tLw=="},  # not STS
            {"iam_request_body": "QWN0aW9uPUFzc3VtZVJvbGU="},  # not GetCallerIdentity
            {"iam_request_headers": "e30="},  # {} — unsigned
            {"iam_request_url": "not base64 at all"},
        ],
    )
    def test_a_mangled_aws_payload_is_rejected(self, overrides):
        assert reject_login("aws", self._aws_payload(**overrides)) is not None

    def test_a_non_jwt_identity_token_is_rejected(self):
        assert reject_login("kubernetes", {"role": "warpgate", "jwt": "a-token"})
        assert reject_login("kubernetes", {"role": "warpgate", "jwt": SERVICE_ACCOUNT_JWT}) is None

    def test_a_gcp_token_for_another_role_is_rejected(self):
        from .stub_vault import jwt

        assert reject_login(
            "gcp", {"role": "warpgate", "jwt": jwt({"aud": "vault/other-role"})}
        )
        assert (
            reject_login("gcp", {"role": "warpgate", "jwt": jwt({"aud": "vault/warpgate"})})
            is None
        )

    def test_azure_coordinates_are_all_required(self):
        from .stub_vault import jwt

        complete = {
            "role": "warpgate",
            "jwt": jwt({"aud": "https://management.azure.com/"}),
            "subscription_id": "sub-1",
            "resource_group_name": "rg-1",
            "vm_name": "vm-1",
        }
        assert reject_login("azure", complete) is None
        for field in ("subscription_id", "resource_group_name", "vm_name"):
            assert reject_login("azure", {**complete, field: ""}), f"{field} not checked"


class TestControlsStillApply:
    """A new authentication path is the classic place for an existing control to
    go missing — the shape of GHSA-qmr2-wp96-h9ff."""

    def test_an_unauthorized_user_never_reaches_the_issuer(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        user, target = make_user_and_target(api, cert_ssh_port, assign=False)
        code, _ = connect(processes, cert_wg, user, target, timeout)

        assert code != 0
        assert stub_vault.signs == [], "a certificate was issued before authorization"

    def test_a_role_that_climbs_out_of_the_mount_never_leaves_the_process(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """The role is put into the request path, and a URL is normalised before
        it is sent: `../../auth/token/create` would arrive at a different Vault
        API altogether, with the gateway's own token attached to it.

        Refused when the target is saved, which is the first moment anyone can
        be told. It used to be refused only when a session tried to use it, so
        the admin learned of it from a broken connection hours later.

        The signing path still refuses it — `validate_segment` in
        `warpgate-vault`, held by `test_segment_validation` — and that layer is
        now unreachable through the API, which is the point of refusing early.
        Both layers read the same rule from `warpgate_common`, so they cannot
        drift into disagreeing about what a role may be called.
        """
        with pytest.raises(sdk.ApiException) as refused:
            make_user_and_target(api, cert_ssh_port, role="../../auth/token/create")
        assert refused.value.status == 400, refused.value.status
        assert stub_vault.requests == [], "a request left the process"

        # Which only means something if a target that names a real role does
        # reach Vault from this same gateway.
        user, target = make_user_and_target(api, cert_ssh_port)
        assert connect(processes, cert_wg, user, target, timeout)[0] == 0
        assert stub_vault.requests

    def test_no_certificate_is_issued_for_targets_using_other_auth(
        self, processes, cert_wg, stub_vault, api, timeout, wg_c_ed25519_pubkey
    ):
        port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(port)

        wg_role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        api.create_public_key_credential(
            user.id,
            sdk.NewPublicKeyCredential(
                label="Public Key",
                openssh_public_key=USER_PUBLIC_KEY_PATH.read_text().strip(),
            ),
        )
        api.add_user_role(user.id, wg_role.id)
        target = api.create_target(
            sdk.TargetDataRequest(
                name=f"pubkey-{uuid4()}",
                options=sdk.TargetOptions(
                    sdk.TargetOptionsTargetSSHOptions(
                        kind="Ssh",
                        host=TARGET_HOST,
                        port=port,
                        username="root",
                        auth=sdk.SSHTargetAuth(
                            sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                        ),
                    )
                ),
            )
        )
        api.add_target_role(target.id, wg_role.id)

        connect(processes, cert_wg, user, target, timeout)
        assert stub_vault.signs == []


class TestSecrets:
    def test_the_vault_token_is_never_logged(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        user, target = make_user_and_target(api, cert_ssh_port)
        # The gateway logs in once and caches the token, and both fixtures here
        # are module-scoped, so a test that simply reads `valid_token` checks a
        # string some earlier test's login produced. Invalidating first makes
        # this connection do its own login, and the assertion below proves it.
        logins_before = len(stub_vault.logins)
        stub_vault.invalidate_token()
        connect(processes, cert_wg, user, target, timeout)

        assert len(stub_vault.logins) > logins_before, (
            "the gateway never logged in, so the token below is not one it presented"
        )
        assert stub_vault.valid_token
        log = Path(cert_wg.log_path).read_text()
        # Asserted so the check below cannot pass merely because nothing was logged.
        assert "Issued an SSH certificate" in log
        assert stub_vault.valid_token not in log

    def test_no_credential_reaches_the_log_even_at_trace_level(
        self, processes: ProcessManager, ctx, stub_vault, cert_ssh_port, timeout
    ):
        """Trace is where an operator goes when sessions will not connect, so it
        is the setting most likely to be on while something is going wrong — and
        the output most likely to be pasted into an issue. Neither the
        credential Warpgate authenticates with nor the token it gets back may be
        in it, at any verbosity."""
        token_path = ctx.tmpdir / f"sa-token-{uuid4()}"
        token_path.write_text(SERVICE_ACCOUNT_JWT)

        log_path = ctx.tmpdir / f"trace-wg-{uuid4()}.log"
        with log_path.open("w") as log:
            wg = processes.start_wg(
                config_patch={
                    "vault": {
                        "address": stub_vault.url,
                        "ca_bundle": stub_vault.ca_bundle,
                        "default_role": "warpgate",
                        "auth": {
                            "kind": "kubernetes",
                            "role": "warpgate",
                            "token_path": str(token_path),
                        },
                    }
                },
                env={"RUST_LOG": "trace"},
                stdout=log,
                stderr=log,
            )
            wait_port(wg.http_port, for_process=wg.process, recv=False)
            wait_port(wg.ssh_port, for_process=wg.process)

            with admin_client(f"https://localhost:{wg.http_port}") as api:
                user, target = make_user_and_target(api, cert_ssh_port)
            assert connect(processes, wg, user, target, timeout)[0] == 0

        text = Path(log_path).read_text(errors="replace")
        # Both halves of the exchange happened, so the log had the chance.
        assert "Issued an SSH certificate" in text
        assert stub_vault.logins and stub_vault.valid_token

        assert stub_vault.valid_token not in text, "the Vault token is in the log"
        assert SERVICE_ACCOUNT_JWT not in text, "the service account token is in the log"
        assert SERVICE_ACCOUNT_JWT.split(".")[1] not in text, "its claims are in the log"

    def test_no_ephemeral_key_is_stored(
        self, processes, cert_wg, cert_ssh_port, api, timeout
    ):
        """The whole point of the feature: nothing the target would trust may
        outlive the connection."""
        before = len(api.get_ssh_own_keys())

        user, target = make_user_and_target(api, cert_ssh_port)
        assert connect(processes, cert_wg, user, target, timeout)[0] == 0

        assert len(api.get_ssh_own_keys()) == before


class TestAChainWithAJumpHost:
    """Every other test here uses exactly one hop.

    Composition is where identity gets confused — whose key, whose certificate,
    whose account — and the code has a chain resolver that reverses its list.
    Not testing it is how the host-key check came to report the jump host's key
    as the target's.
    """

    def _chain(self, api, jump_port, target_port, extensions=None):
        """A target reached through a jump host, both on certificate auth."""
        wg_role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        api.create_public_key_credential(
            user.id,
            sdk.NewPublicKeyCredential(
                label="Public Key",
                openssh_public_key=USER_PUBLIC_KEY_PATH.read_text().strip(),
            ),
        )
        api.add_user_role(user.id, wg_role.id)

        def make(name, port, jump=None, host=TARGET_HOST, extensions=None):
            options = sdk.TargetOptionsTargetSSHOptions(
                kind="Ssh",
                host=host,
                port=port,
                username="root",
                auth=sdk.SSHTargetAuth(
                    sdk.SSHTargetAuthSshTargetCertificateAuth(
                        kind="Certificate",
                        role=None,
                        allowed_critical_options=[],
                        allowed_extensions=extensions or ["permit-pty"],
                    )
                ),
            )
            if jump is not None:
                options.jump_host = jump
            target = api.create_target(
                sdk.TargetDataRequest(name=name, options=sdk.TargetOptions(options))
            )
            api.add_target_role(target.id, wg_role.id)
            return target

        # A target used as a jump host needs `permit-port-forwarding` on its own
        # certificate: Warpgate reaches the next hop by opening a direct-tcpip
        # channel through it, and OpenSSH judges that purely on what the
        # certificate carries. Naming it here is the point of the allow-list —
        # before it existed every certificate carried this silently.
        jump = make(
            f"jump-{uuid4()}",
            jump_port,
            extensions=["permit-pty", "permit-port-forwarding"],
        )
        # Dialled from inside the jump host's container, where `localhost` is
        # the container itself.
        target = make(
            f"behind-{uuid4()}",
            target_port,
            jump=jump.id,
            host="host.docker.internal",
            extensions=extensions,
        )
        return user, jump, target

    def _two_fresh_hops(self, processes, api, stub_vault):
        """A chain whose two hops have never been seen by anything.

        Freshly started, so neither key is trusted whatever ran before — the
        jump host used to be the file's shared fixture server, which earlier
        tests connect to, and a test whose subject is *whether a key is trusted*
        cannot borrow a server whose key another test has already trusted.

        Each hop gets a key of its own too: two servers sharing one are
        indistinguishable to exactly the thing under test.
        """
        stub_vault.sign_options = ["permit-port-forwarding"]
        jump_port = processes.start_ssh_server(
            trusted_ca=[stub_vault.ca_public_key], distinct_host_key=True
        )
        target_port = processes.start_ssh_server(
            trusted_ca=[stub_vault.ca_public_key], distinct_host_key=True
        )
        wait_port(jump_port)
        wait_port(target_port)
        assert processes.host_keys[jump_port] != processes.host_keys[target_port], (
            "the two hops were started with the same key, so nothing below "
            "distinguishes them"
        )
        return (jump_port, target_port, *self._chain(api, jump_port, target_port))

    def test_an_untrusted_jump_host_is_refused_rather_than_traversed(
        self, processes, stub_vault, api
    ):
        """Checking the target's host key goes through the jump host, whose own
        key nothing has trusted yet. Accepting it there would trust a host on
        the strength of a question asked about a different one."""
        jump_port, _, _, _, target = self._two_fresh_hops(processes, api, stub_vault)
        before = len(stub_vault.signs)

        with pytest.raises(sdk.ApiException) as refused:
            api.check_ssh_host_key(sdk.CheckSshHostKeyRequest(target_id=target.id))
        # The message, not just the failure. Without the refusal the hop's key
        # is declined at the transport instead and the endpoint answers "SSH
        # protocol error" — a failure either way, which is why asserting only
        # that this raises would be evidence for nothing.
        assert "untrusted host key" in str(refused.value.body), refused.value.body

        # Refused, and refused early: nothing was authenticated on the way, so
        # no certificate was minted for anyone.
        assert len(stub_vault.signs) == before, "a certificate was issued anyway"
        # And the hop was not quietly trusted in passing, which is the failure
        # this refusal exists to prevent.
        assert not [
            host for host in api.get_ssh_known_hosts() if host.port == jump_port
        ], "the jump host's key was trusted on the way through"

    def test_the_host_key_check_reports_the_target_and_not_the_jump_host(
        self, processes, stub_vault, api
    ):
        """Both hops present a key, and the endpoint used to answer with the
        first one it saw. An operator pinning what they are told is the target's
        key was pinning the jump host's, and the target's own key was never
        looked at."""
        jump_port, target_port, _, _, target = self._two_fresh_hops(
            processes, api, stub_vault
        )

        # The jump host is trusted here the way the admin UI trusts one — by
        # recording its key — rather than by opening a session to it. Trusting
        # it by connecting would make this test depend on the host-key
        # verification mode, a single global parameter that any test sharing
        # this gateway can change, and the point of this one is to depend on
        # nothing but its own two servers.
        jump_key = processes.host_keys[jump_port]
        api.add_ssh_known_host(
            sdk.AddSshKnownHostRequest(
                host=TARGET_HOST,
                port=jump_port,
                key_type=jump_key.key_type,
                key_base64=jump_key.base64,
            )
        )

        reported = api.check_ssh_host_key(
            sdk.CheckSshHostKeyRequest(target_id=target.id)
        )

        # By identity, not by elimination. "Not the jump host's key" and "the
        # target's key" are the same claim for a chain of two and stop being the
        # same for a chain of three, and the weaker one is what this test made
        # until an outside verifier read it (W-119).
        target_key = processes.host_keys[target_port]
        assert reported.remote_key_base64 != jump_key.base64, (
            "checking the target answered with the jump host's key"
        )
        assert (reported.remote_key_type, reported.remote_key_base64) == (
            target_key.key_type,
            target_key.base64,
        ), "the reported key is not the one the target was started with"

    def test_checking_a_chained_target_authenticates_only_to_the_jump_host(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """Reaching the target's transport means authenticating to the jump
        host first — there is no tunnel otherwise — so one certificate is
        minted, for the hop that is traversed. The target itself is stopped at
        its host key, before anything is offered to it."""
        stub_vault.sign_options = ["permit-port-forwarding"]
        second = processes.start_ssh_server(
            trusted_ca=[stub_vault.ca_public_key], distinct_host_key=True
        )
        wait_port(second)

        user, jump, target = self._chain(api, cert_ssh_port, second)
        assert connect(processes, cert_wg, user, jump, timeout)[0] == 0

        before = len(stub_vault.signs)
        api.check_ssh_host_key(sdk.CheckSshHostKeyRequest(target_id=target.id))
        minted = stub_vault.signs[before:]

        assert len(minted) == 1, f"expected one certificate for the jump host, got {len(minted)}"

        # And it has to name whoever asked. There is no session to look up here
        # — a button press is not a login — so the key ID used to fall back to
        # the random UUID that stood in for one, and both the jump host's sshd
        # log and Vault's issuance log recorded a certificate resolving to
        # nobody.
        #
        # `admin-token`, not `admin`: this suite authenticates with an API
        # token, which carries no username, and the first version of the fix
        # substituted the literal string "admin" for it — recording an API call
        # as though a person by that name had opened the session. That is the
        # same attribution failure one layer along, so the label says what it
        # actually was.
        key_id = minted[0]["key_id"]
        assert key_id.startswith("warpgate:admin-token:"), (
            f"the certificate misnames who asked: {key_id}"
        )

    def test_a_session_through_a_jump_host_works(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """The chain still has to work, and each hop gets its own certificate
        naming its own account."""
        # The stub signs one set of options for every request, where real Vault
        # would use a role per target. So the leaf has to permit what the jump
        # host needs; the two host-key checks above, which traverse the jump
        # host on the leaf's own allow-list, are where it does its work.
        stub_vault.sign_options = ["permit-port-forwarding"]
        second = processes.start_ssh_server(trusted_ca=[stub_vault.ca_public_key])
        wait_port(second)

        user, _, target = self._chain(
            api, cert_ssh_port, second, extensions=["permit-pty", "permit-port-forwarding"]
        )
        assert connect(processes, cert_wg, user, target, timeout)[0] == 0

        assert len(stub_vault.signs) == 2, "each hop needs its own certificate"
        assert all(sign["valid_principals"] == "root" for sign in stub_vault.signs)
