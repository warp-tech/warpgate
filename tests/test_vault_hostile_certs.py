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


from .api_client import admin_client, sdk
from .conftest import TARGET_HOST, ProcessManager, WarpgateProcess
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
        # Without this the test passes just as well when the certificate path
        # never ran at all.
        assert stub_vault.signs, "no certificate was ever requested"

    def test_a_certificate_with_a_different_key_id_is_refused(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """The key ID is the attribution, so a substituted one has to be caught.

        A plausible substitution rather than an absurd one: `sshd` accepts any
        key ID at all and writes it to its log, so a target refuses nothing here
        and a test asserting only a non-zero exit code proves nothing about our
        check. The assertion is on Warpgate's own words.

        This test is the reason the matrix now verifies that a named
        discriminator exists. The entry for this guard named exactly this
        function for a week; it had never been written, and the guard was
        reported on regardless.
        """
        from .test_ssh_target_cert_auth import make_user_and_target, start

        stub_vault.sign_key_id = "warpgate:someone-else:00000000"
        user, target = make_user_and_target(api, cert_ssh_port)

        client = start(processes, cert_wg, user, target, "-tt")
        shown = client.communicate(timeout=timeout)[0].decode(errors="replace")

        assert stub_vault.signs, "no certificate was ever requested"
        assert client.returncode != 0, "a certificate naming another user was offered"
        assert "Warpgate refused the certificate" in shown
        assert "key ID other than the one requested" in shown

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
        """The whole point of the feature is a short window. A certificate good for
        ten years defeats it."""
        from .test_ssh_target_cert_auth import make_user_and_target, start

        # `+36500d` is refused by ssh-keygen itself, so the stub used to crash and
        # the session failed on "Vault is currently unavailable" — passing this
        # test without a long-lived certificate ever existing.
        stub_vault.validity = "-1d:+3650d"
        user, target = make_user_and_target(api, cert_ssh_port)

        # Asked with a PTY and checked by *who* refused. A century-long
        # certificate is one sshd is perfectly happy with, so asserting only
        # that the session failed would pass on a rejection from the target —
        # which is what the mutation matrix caught this test doing.
        client = start(processes, cert_wg, user, target, "-tt")
        shown = client.communicate(timeout=timeout)[0].decode(errors="replace")

        assert stub_vault.signs, "no certificate was issued"
        assert client.returncode != 0, "a certificate valid for a century was accepted"
        assert "Warpgate refused the certificate" in shown
        assert "far longer than a session credential" in shown

    def test_a_certificate_carrying_a_hundred_critical_options(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """Refusal has to survive the loop over them.

        Asked with a PTY and checked by *who* refused. These names are ones
        OpenSSH does not recognise, so a target refuses the certificate on its
        own — and asserting only a non-zero exit code passes just as well with
        our own check deleted, which is what the certificate never reaching the
        target would look like either way.
        """
        from .test_ssh_target_cert_auth import make_user_and_target, start

        stub_vault.sign_options = [f"critical:opt{n}=v" for n in range(100)]
        user, target = make_user_and_target(api, cert_ssh_port)

        client = start(processes, cert_wg, user, target, "-tt")
        shown = client.communicate(timeout=timeout)[0].decode(errors="replace")

        assert stub_vault.signs, "no certificate was ever requested"
        assert client.returncode != 0, "a certificate carrying 100 options was accepted"
        assert "Warpgate refused the certificate" in shown
        assert "does not allow" in shown

    def test_a_signed_key_that_is_not_a_certificate_at_all(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        stub_vault.signed_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHNvbWV0aGluZw== not-a-cert"
        code, _ = attempt(processes, cert_wg, api, cert_ssh_port, timeout)
        assert code != 0
        # Without this the test passes just as well when the certificate path
        # never ran at all.
        assert stub_vault.signs, "no certificate was ever requested"

    def test_a_signed_key_that_is_a_megabyte_of_base64(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        stub_vault.signed_key = "ssh-ed25519-cert-v01@openssh.com " + ("A" * 1024 * 1024)
        code, _ = attempt(processes, cert_wg, api, cert_ssh_port, timeout)
        assert code != 0
        # Without this the test passes just as well when the certificate path
        # never ran at all.
        assert stub_vault.signs, "no certificate was ever requested"

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
        # The negative assertion alone is satisfied by the message never
        # arriving — a connection that dies before writing anything contains no
        # escape sequences either. Every sibling in this file anchors on the
        # refusal first; this one did not, and so proved only that *something*
        # went wrong. The option name's printable tail pins the third case
        # apart: the message reached the terminal, it named the option, and the
        # escape was neutralised rather than the name being dropped.
        assert "Warpgate refused the certificate" in stdout
        # `HACKED`, not `HACKED=x`: `ssh-keygen` splits `critical:NAME=VALUE` on
        # the first `=`, so the value is not part of the name the message
        # quotes. Asserted wrongly once, and the run said so.
        assert "HACKED" in stdout, "the refusal did not name the option at all"
        # Neutralised rather than dropped. The escape has to be *present* in its
        # inert form, or a fix that silently strips the option name would pass
        # the two assertions above and the one below.
        assert "\\u{1b}[2J" in stdout, "the escape was removed rather than escaped"
        assert "\x1b[2J" not in stdout, "a certificate wrote escape sequences to the terminal"

    def test_a_pinned_option_that_is_absent_is_refused(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """The allow-list was built against someone who *adds* an option nobody
        asked for. Approached from the other side they remove an expected one,
        and a target whose whole point is a pinned `force-command` would accept
        a certificate carrying none — a full shell instead of the one command.

        Checking only what arrived can never see this, which is why every check
        here needs its complement."""
        from .test_ssh_target_cert_auth import connect, make_user_and_target

        stub_vault.sign_options = []
        user, target = make_user_and_target(
            api,
            cert_ssh_port,
            allowed_critical_options=[("force-command", "/usr/local/bin/backup")],
        )
        code, stdout = connect(processes, cert_wg, user, target, timeout)

        assert stub_vault.signs, "no certificate was issued"
        assert code != 0, "a certificate without the required option was accepted"
        assert b"/bin/sh" not in stdout, "the session got a shell"

    def test_a_pinned_option_that_is_present_still_works(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """The complement of the complement: requiring the option must not break
        the case it was written for."""
        from .test_ssh_target_cert_auth import connect, make_user_and_target

        stub_vault.sign_options = ["force-command=echo expected-by-the-operator"]
        user, target = make_user_and_target(
            api,
            cert_ssh_port,
            allowed_critical_options=[
                ("force-command", "echo expected-by-the-operator")
            ],
        )

        assert connect(processes, cert_wg, user, target, timeout) == (
            0,
            b"expected-by-the-operator\n",
        )


class TestTheCredentialFileItself:
    """The file a credential is read from is as much an input as anything on the
    wire — it is written by whatever provisions the host, which can be wrong."""

    def test_a_credential_file_too_large_to_be_one_is_refused(
        self, processes: ProcessManager, ctx, stub_vault, cert_ssh_port, timeout
    ):
        """Reading it would outgrow the buffer reserved for the login payload
        and reintroduce the grow-and-copy leak that reservation exists to
        prevent — silently, since nothing else would notice."""
        from .test_ssh_target_cert_auth import connect, make_user_and_target

        token_path = ctx.tmpdir / f"huge-token-{uuid4()}"
        token_path.write_text("x" * (64 * 1024))

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
            user, target = make_user_and_target(api, cert_ssh_port)

        assert connect(processes, wg, user, target, timeout)[0] != 0

        # `logins` records only payloads the stub accepted, so a request that
        # was sent and then rejected leaves it empty too — which made the first
        # version of this assertion true either way. `requests` records every
        # path before any validation, so it can tell "never sent" from "sent
        # and refused".
        assert not any("/login" in path for path in stub_vault.requests), (
            "an oversized credential was sent to the issuer"
        )

    def test_a_very_long_username_cannot_flood_the_targets_log(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """The key ID exists so the target's own log names a person. A username
        long enough to bury that log defeats it just as surely as a wrong name,
        and the check on the *returned* key ID cannot see it — that one compares
        against what was asked for, so an oversized request matches itself."""
        from .test_ssh_target_cert_auth import connect, USER_PUBLIC_KEY_PATH

        wg_role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        user = api.create_user(
            sdk.CreateUserRequest(username="u" * 4000 + str(uuid4()))
        )
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
                        port=cert_ssh_port,
                        username="root",
                        auth=sdk.SSHTargetAuth(
                            sdk.SSHTargetAuthSshTargetCertificateAuth(
                                kind="Certificate", role=None, allowed_critical_options=[]
                            )
                        ),
                    )
                ),
            )
        )
        api.add_target_role(target.id, wg_role.id)

        assert connect(processes, cert_wg, user, target, timeout)[0] != 0
        # Refused before it is sent, so no oversized key ID is signed either.
        assert stub_vault.signs == [], "an oversized key ID was sent to the issuer"

    def test_a_certificate_that_never_expires(
        self, processes, cert_wg, cert_ssh_port, stub_vault, api, timeout
    ):
        """The lifetime bound reads `valid_before_time()`, which `ssh-key`
        documents as returning `None` when the value overflows `i64` — i.e. for
        a certificate marked never-expiring. So the check that exists to refuse a
        credential which outlives its session is skipped by the one input an
        adversary would reach for first.

        `-V always:forever` is what produces it, and it is also what a role with
        no TTL at all yields."""
        from .test_ssh_target_cert_auth import make_user_and_target, start

        stub_vault.validity = "always:forever"
        user, target = make_user_and_target(api, cert_ssh_port)

        # `-tt`, like every sibling in this file. This was skipped on the
        # reasoning that the target holds an interactive session open past the
        # timeout — but the target never sees this certificate at all: Warpgate
        # refuses it before offering it, and without a PTY there is no channel
        # for `emit_pty_output` to write the refusal to, so the client waits on
        # a session that will never open. The forty-five seconds were the
        # client's own timeout, not the target's.
        client = start(processes, cert_wg, user, target, "-tt")
        shown = client.communicate(timeout=timeout)[0].decode(errors="replace")

        assert stub_vault.signs, "no certificate was issued"
        assert client.returncode != 0, "a never-expiring certificate was accepted"
        assert "Warpgate refused the certificate" in shown
        # The specific refusal, not just any. The exit code and the absence of a
        # shell are satisfied by every other way this connection can fail, so on
        # their own they would have passed with the guard deleted.
        assert "never expires" in shown
        assert "/bin/sh" not in shown
