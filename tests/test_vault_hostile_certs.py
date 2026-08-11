"""Certificates a well-behaved issuer would never produce.

Warpgate now checks what comes back — type, key, principals, critical options —
and each of those checks was added because something got through. These are the
shapes nobody has pointed at yet: absurd sizes, absurd validity, more principals
than anyone would name, a key ID as long as the certificate itself.

None of these should authenticate. What is under test is that each fails as an
authentication failure, in bounded time, with the gateway still standing.
"""

from uuid import uuid4

import pytest

from .api_client import admin_client
from .conftest import ProcessManager, WarpgateProcess
from .stub_vault import SERVICE_ACCOUNT_JWT, StubVault
from .util import wait_port

USER_PUBLIC_KEY_PATH = "ssh-keys/id_ed25519.pub"


@pytest.fixture(scope="module")
def stub_vault(ctx):
    stub = StubVault(ctx.tmpdir / f"hostile-vault-{uuid4()}")
    stub.start()
    yield stub
    stub.stop()


@pytest.fixture(scope="module")
def cert_wg(processes: ProcessManager, ctx, stub_vault):
    token_path = ctx.tmpdir / f"sa-token-{uuid4()}"
    token_path.write_text(SERVICE_ACCOUNT_JWT)
    wg = processes.start_wg(
        config_patch={
            "vault": {
                "address": stub_vault.url,
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
    return wg


@pytest.fixture(scope="module")
def cert_ssh_port(processes: ProcessManager, stub_vault):
    port = processes.start_ssh_server(trusted_ca=[stub_vault.ca_public_key])
    wait_port(port)
    return port


@pytest.fixture(autouse=True)
def reset_stub(stub_vault):
    stub_vault.reset()
    yield
    stub_vault.reset()


@pytest.fixture
def api(cert_wg: WarpgateProcess):
    with admin_client(f"https://localhost:{cert_wg.http_port}") as client:
        yield client


def attempt(processes, cert_wg, api, cert_ssh_port, timeout, **target_kwargs):
    from .test_ssh_target_cert_auth import connect, make_user_and_target

    user, target = make_user_and_target(api, cert_ssh_port, **target_kwargs)
    return connect(processes, cert_wg, user, target, timeout)


class TestCertificatesNobodyShouldAccept:
    def test_a_key_id_far_larger_than_the_certificate(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """The key ID is chosen by Warpgate, but the issuer decides what it puts
        in the certificate it returns. A 64 KiB one must not become 64 KiB in
        the target's log — or in ours."""
        stub_vault.sign_key_id = "A" * 65536
        code, _ = attempt(processes, cert_wg, api, cert_ssh_port, timeout)
        assert code != 0

    def test_a_certificate_naming_a_thousand_principals(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """`root` is in there, so the target would accept it. Warpgate should
        not: nobody asked for the other 999, and the set is meant to be what was
        requested."""
        stub_vault.principals = ",".join([f"user{n}" for n in range(999)] + ["root"])
        code, _ = attempt(processes, cert_wg, api, cert_ssh_port, timeout)
        assert stub_vault.signs, "no certificate was issued"
        assert code != 0, "a certificate naming a thousand accounts was offered"

    def test_a_certificate_valid_for_a_century(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """The whole point of the feature is a short window. A certificate good
        until 2126 defeats it — worth knowing whether anything notices."""
        stub_vault.validity = "-1d:+36500d"
        code, _ = attempt(processes, cert_wg, api, cert_ssh_port, timeout)
        assert stub_vault.signs, "no certificate was issued"
        # Recorded rather than asserted: sshd accepts it, and Warpgate does not
        # currently police the upper bound. See SECURITY_TESTING.md.
        assert code in (0, 255)

    def test_a_certificate_carrying_a_hundred_critical_options(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """Refusal has to survive the loop over them."""
        stub_vault.sign_options = [f"critical:opt{n}=v" for n in range(100)]
        code, _ = attempt(processes, cert_wg, api, cert_ssh_port, timeout)
        assert code != 0

    def test_a_signed_key_that_is_not_a_certificate_at_all(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        stub_vault.signed_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHNvbWV0aGluZw== not-a-cert"
        code, _ = attempt(processes, cert_wg, api, cert_ssh_port, timeout)
        assert code != 0

    def test_a_signed_key_that_is_a_megabyte_of_base64(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        stub_vault.signed_key = "ssh-ed25519-cert-v01@openssh.com " + ("A" * 1024 * 1024)
        code, _ = attempt(processes, cert_wg, api, cert_ssh_port, timeout)
        assert code != 0

    def test_the_gateway_survives_all_of_it(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """Runs last: after everything above, an ordinary session must still
        work. A panic in any of those paths would show up here."""
        code, stdout = attempt(processes, cert_wg, api, cert_ssh_port, timeout)
        assert (code, stdout) == (0, b"/bin/sh\n")


class TestWhatTheOperatorIsTold:
    """The README warns that a target whose clock lags rejects a short-lived
    certificate "with an error that does not say so". The container's clock
    cannot be moved without `SYS_TIME`, but the condition sshd sees is the same
    one a certificate outside its window produces — and what the person
    connecting is told is worth asserting, since that is what they debug from."""

    def test_a_certificate_that_is_not_yet_valid(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        from .test_ssh_target_cert_auth import make_user_and_target, start

        stub_vault.validity = "+1h:+2h"
        user, target = make_user_and_target(api, cert_ssh_port)

        client = start(processes, cert_wg, user, target, "-tt")
        stdout = client.communicate(timeout=timeout)[0].decode(errors="replace")

        assert client.returncode != 0
        assert stub_vault.signs, "no certificate was issued"
        # The window and the hint are the whole point: "rejected by the target"
        # on its own sends someone to check credentials that are perfectly fine.
        assert "check the target's clock" in stdout
        assert "valid from" in stdout


class TestPrincipalsThatCrossOtherPeoplesBugs:
    """A principal is not only ours to interpret — the target's sshd parses it
    too, and has been wrong about it.

    CVE-2026-35414: a comma inside a certificate principal breaks OpenSSH's
    access control (8.5p1 through 9.7p1), because one validation function splits
    on the comma and authenticates the first fragment while the next treats the
    whole string as one name. A certificate naming `deploy,root` can therefore
    land a session as root.

    Warpgate already refuses to *request* a principal with a comma in it. The
    question here is what it does with one that comes *back*.
    """

    def test_a_certificate_naming_more_than_the_target_account_is_refused(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """`root` is present, so a membership check passes and the session
        would succeed. The second name is an account the target will also
        accept this certificate for, chosen by whoever answered rather than by
        the operator — and under `AuthorizedPrincipalsFile` it need not look
        like a username at all."""
        stub_vault.principals = "root,deploy"
        code, _ = attempt(processes, cert_wg, api, cert_ssh_port, timeout)

        assert stub_vault.signs, "no certificate was issued"
        assert code != 0, "a certificate naming accounts nobody asked for was offered"

    def test_a_hostile_option_name_cannot_write_to_the_terminal(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """The refusal message quotes the option name straight from the
        certificate and is written to the user's terminal. Escape sequences in
        it would be executed by the terminal, not displayed — the same class as
        GHSA-3c3w, one layer down."""
        from .test_ssh_target_cert_auth import make_user_and_target, start

        stub_vault.sign_options = ["critical:\x1b[2J\x1b[1;31mHACKED=x"]
        user, target = make_user_and_target(api, cert_ssh_port)

        client = start(processes, cert_wg, user, target, "-tt")
        stdout = client.communicate(timeout=timeout)[0].decode(errors="replace")

        assert client.returncode != 0
        assert stub_vault.signs, "no certificate was issued"
        assert "\x1b[2J" not in stdout, "a certificate wrote escape sequences to the terminal"
