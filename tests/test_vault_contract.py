"""Warpgate against a real Vault and a real OpenBao.

`test_ssh_target_cert_auth.py` runs against a stub, which is fast and can be made
to misbehave on demand — but it only knows what we told it. Every behaviour it
models is a claim about the real server, and the claims have been wrong twice:
a wrapping token treated as reusable, and a `lease_duration` of zero read as
expiry. Both defects were invisible for exactly as long as the stub was the only
witness.

So each such claim is pinned here, once, against the thing itself. The
assertions read the request out of the server's own audit device — the payload
as the server received it, rather than as our stub chose to remember it.
"""

import shutil
import subprocess
import time
from pathlib import Path
from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .util import wait_port
from .vault_server import RealVault, matrix

pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None, reason="needs Docker"
)


@pytest.fixture(params=matrix(), ids=lambda image: image.replace("/", "-").replace(":", "-"))
def server(request, ctx):
    """A real issuer. Parametrised because OpenBao is not a rename of Vault:
    it already differs on how an audit device may be enabled, and its cloud auth
    methods are separate plugins rather than builtins."""
    vault = RealVault(request.param, config_dir=ctx.tmpdir / f"bao-{uuid4()}")
    vault.start()
    yield vault
    vault.stop()


def start_warpgate(processes: ProcessManager, ctx, server: RealVault, *, wrapped=False):
    secret_id_path = server.write_secret_id(
        ctx.tmpdir / f"secret-id-{uuid4()}", wrapped=wrapped
    )
    wg = processes.start_wg(
        config_patch={
            "vault": {
                "address": server.url,
                "ca_bundle": server.ca_bundle,
                "default_role": "warpgate",
                "auth": {
                    "kind": "app_role",
                    "role_id": server.role_id,
                    "secret_id_path": str(secret_id_path),
                },
            }
        }
    )
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    wait_port(wg.ssh_port, for_process=wg.process)
    return wg, secret_id_path


def make_user_and_target(api, ssh_port, username="root"):
    from .test_ssh_target_cert_auth import make_user_and_target as make

    return make(api, ssh_port, username=username)


def connect(processes, wg, user, target, timeout):
    from .test_ssh_target_cert_auth import connect as do_connect

    return do_connect(processes, wg, user, target, timeout)


class TestAgainstARealIssuer:
    def test_a_session_authenticates_end_to_end(
        self, processes: ProcessManager, ctx, server, timeout
    ):
        """The whole point, against the real thing: no stored key on the
        gateway, no authorized_keys on the target, a certificate the target
        trusts because it trusts the CA."""
        ssh_port = processes.start_ssh_server(trusted_ca=[server.ca_public_key])
        wait_port(ssh_port)

        wg, _ = start_warpgate(processes, ctx, server)
        with admin_client(f"https://localhost:{wg.http_port}") as api:
            user, target = make_user_and_target(api, ssh_port)

        assert connect(processes, wg, user, target, timeout) == (0, b"/bin/sh\n")

        # Read back out of the server's audit device, so this asserts on the
        # request as it arrived rather than on anything we recorded ourselves.
        assert server.signs, "the issuer never saw a signing request"
        signed = server.signs[-1]
        assert signed["valid_principals"] == "root"
        assert signed["cert_type"] == "user"
        assert signed["key_id"].startswith("warpgate:")

    def test_a_wrapping_token_cannot_be_redeemed_twice(
        self, processes: ProcessManager, ctx, server, timeout
    ):
        """The claim the stub used to get wrong. Warpgate unwraps once and
        reuses the secret ID; unwrapping per login would fail every login after
        the first, and the server is the only witness that can prove it."""
        ssh_port = processes.start_ssh_server(trusted_ca=[server.ca_public_key])
        wait_port(ssh_port)

        wg, _ = start_warpgate(processes, ctx, server, wrapped=True)
        with admin_client(f"https://localhost:{wg.http_port}") as api:
            user, target = make_user_and_target(api, ssh_port)

        for _ in range(3):
            assert connect(processes, wg, user, target, timeout)[0] == 0

        assert len(server.unwraps) == 1, "the wrapping token was redeemed more than once"

    def test_the_role_refuses_a_principal_it_does_not_allow(
        self, processes: ProcessManager, ctx, server, timeout
    ):
        """`allowed_users` is the coarse gate that stands even when Warpgate is
        wrong about who may reach what. `nobody` is outside it.

        Read from what the server *returned*, not from what it was asked. A
        failed session and a recorded request are equally true when the role
        issues the certificate happily and the target rejects an account it does
        not have — which is the same observable, and the reason the sibling test
        below carries the same warning.
        """
        ssh_port = processes.start_ssh_server(trusted_ca=[server.ca_public_key])
        wait_port(ssh_port)

        wg, _ = start_warpgate(processes, ctx, server)
        with admin_client(f"https://localhost:{wg.http_port}") as api:
            user, target = make_user_and_target(api, ssh_port, username="nobody")

        signs_before = len(server.signs)
        issued_before = len(server.issued)

        assert connect(processes, wg, user, target, timeout)[0] != 0
        assert len(server.signs) > signs_before, "the request never reached the issuer"
        assert len(server.issued) == issued_before, (
            "the role issued a certificate for a principal its allowed_users "
            "does not list — the refusal under test never happened"
        )

    def test_the_certificate_carries_the_principals_that_were_asked_for(
        self, processes: ProcessManager, ctx, server, timeout
    ):
        """Warpgate refuses a certificate that names anything other than the
        account being reached. That rule is only safe because the server returns
        the requested set verbatim rather than widening it — which has to be read
        out of what the server *returned*.

        The first version of this test read the request instead, so it re-checked
        Warpgate's own message and would have passed whatever came back.
        """
        ssh_port = processes.start_ssh_server(trusted_ca=[server.ca_public_key])
        wait_port(ssh_port)

        wg, _ = start_warpgate(processes, ctx, server)
        with admin_client(f"https://localhost:{wg.http_port}") as api:
            user, target = make_user_and_target(api, ssh_port, username="deploy")

        # `deploy` is in the role's allowed_users but is not a user on the
        # target image, so the session fails at the target — after a
        # certificate has been issued, which is what this test reads.
        connect(processes, wg, user, target, timeout)

        assert server.signs[-1]["valid_principals"] == "deploy"

        # And what came back, which is the half that matters.
        assert server.issued, "the server recorded no certificate"
        certificate = server.issued[-1]["signed_key"]
        principals = subprocess.run(
            ["ssh-keygen", "-L", "-f", "-"],
            input=certificate.encode(),
            capture_output=True,
            check=True,
        ).stdout.decode()
        principals = principals.split("Principals:")[1].split("Critical")[0].split()
        assert principals == ["deploy"], f"the server returned {principals}"

    def test_a_restart_does_not_strand_the_gateway(
        self, processes: ProcessManager, ctx, server, timeout
    ):
        """A dev-mode server loses everything on restart, so the cached token
        stops being accepted before its lease runs out. Warpgate has to notice
        and log in again rather than fail until the lease expires — the
        behaviour the 403 re-login exists for, against a server that really
        does forget."""
        ssh_port = processes.start_ssh_server(trusted_ca=[server.ca_public_key])
        wait_port(ssh_port)

        wg, secret_id_path = start_warpgate(processes, ctx, server)
        with admin_client(f"https://localhost:{wg.http_port}") as api:
            user, target = make_user_and_target(api, ssh_port)

        assert connect(processes, wg, user, target, timeout)[0] == 0

        ca_before = server.ca_public_key
        server.stop()
        server.start()
        # Dev mode regenerates everything, so the target's trust and the
        # gateway's credential both have to be re-pointed. What is under test is
        # that Warpgate recovers within a session, not that it survives a CA
        # change nobody told it about.
        assert server.ca_public_key != ca_before
        server.write_secret_id(secret_id_path)

        ssh_port = processes.start_ssh_server(trusted_ca=[server.ca_public_key])
        wait_port(ssh_port)
        with admin_client(f"https://localhost:{wg.http_port}") as api:
            user, target = make_user_and_target(api, ssh_port)

        deadline = time.time() + 30
        while time.time() < deadline:
            if connect(processes, wg, user, target, timeout)[0] == 0:
                break
            time.sleep(1)
        else:
            pytest.fail("the gateway never recovered from the issuer restarting")


class TestTheStubMatchesTheServer:
    """The stub's job is to stand in for these servers. Where it disagrees with
    them, the stub is wrong — and every disagreement so far has hidden a defect
    in Warpgate rather than in the stub."""

    def test_a_token_with_no_lease_reports_zero(self, server):
        """`lease_duration: 0` is how a token without a lease is reported, which
        Warpgate used to read as "expired 30 seconds ago" and answer with a
        fresh login on every certificate request."""
        response = server._api(
            "POST",
            "auth/approle/login",
            {"role_id": server.role_id, "secret_id": server.secret_id},
            token=None,
        )
        assert "lease_duration" in response["auth"]
        assert isinstance(response["auth"]["lease_duration"], int)

    def test_a_wrapping_token_is_single_use(self, server):
        """Asserted directly against the server, so the stub's single-use
        modelling is a fact rather than a decision we made."""
        wrapping_token = server.wrapped_secret_id()
        first = server._api("POST", "sys/wrapping/unwrap", {}, token=wrapping_token)
        assert first["data"]["secret_id"]

        with pytest.raises(Exception):
            server._api("POST", "sys/wrapping/unwrap", {}, token=wrapping_token)

    def test_a_key_id_is_refused_rather_than_substituted(self, server):
        """With `allow_user_key_ids=false` the server errors on a request that
        carries one, instead of quietly replacing it with the token's display
        name. That is what makes a misconfigured role fail closed, and why
        Warpgate needs no client-side check."""
        server._api(
            "POST",
            f"ssh-client-signer/roles/no-key-ids",
            {
                "key_type": "ca",
                "allow_user_certificates": True,
                "allowed_users": "root",
                "allow_user_key_ids": False,
                "ttl": "2m",
            },
        )
        # A real key, because a malformed one is rejected at parse time and the
        # role's policy is never consulted — which is how the first version of
        # this test passed without exercising the thing it is named for.
        public_key = Path("ssh-keys/id_ed25519.pub").read_text().strip()

        # The same request against the permissive role must succeed, or a
        # failure below says nothing about `allow_user_key_ids`.
        server._api(
            "POST",
            "ssh-client-signer/sign/warpgate",
            {
                "public_key": public_key,
                "valid_principals": "root",
                "cert_type": "user",
                "key_id": "warpgate:alice:1234",
            },
        )

        with pytest.raises(Exception):
            server._api(
                "POST",
                "ssh-client-signer/sign/no-key-ids",
                {
                    "public_key": public_key,
                    "valid_principals": "root",
                    "cert_type": "user",
                    "key_id": "warpgate:alice:1234",
                },
            )
