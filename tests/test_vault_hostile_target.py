"""Warpgate against a target that is not a real SSH server.

The rest of the suite treats the target as honest. This does not. A target runs
on a machine Warpgate does not own, and russh — the library Warpgate is the
*client* half of here — has published pre-authentication panics reachable from
the peer. A compromised host that can hang or crash the gateway takes down more
than its own session.

Two things are under test throughout: the session fails in bounded time, and the
gateway is still able to serve the next one afterwards.
"""

import shutil
import time
from uuid import uuid4

import psutil
import pytest

from .api_client import admin_client, sdk
from .conftest import TARGET_HOST, ProcessManager
from .hostile_ssh_server import MODES, HostileSSHServer
from .stub_vault import SERVICE_ACCOUNT_JWT, StubVault
from .util import wait_port

pytestmark = pytest.mark.skipif(shutil.which("docker") is None, reason="needs Docker")

USER_PUBLIC_KEY_PATH = "ssh-keys/id_ed25519.pub"


@pytest.fixture(scope="module")
def stub_vault(ctx):
    stub = StubVault(ctx.tmpdir / f"hostile-target-vault-{uuid4()}")
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
def honest_target(processes: ProcessManager, stub_vault):
    """Kept alongside the hostile ones so each test can prove the gateway still
    works afterwards. A crash would otherwise look like a passing rejection."""
    port = processes.start_ssh_server(trusted_ca=[stub_vault.ca_public_key])
    wait_port(port)
    return port


@pytest.fixture
def api(cert_wg):
    with admin_client(f"https://localhost:{cert_wg.http_port}") as client:
        yield client


def target_on(api, port):
    from .test_ssh_target_cert_auth import make_user_and_target

    return make_user_and_target(api, port)


# `silent_after_banner` is left out here and tested on its own: it is bounded by
# the 30s handshake deadline rather than failing immediately, which needs a
# longer client timeout than the rest of these want.
@pytest.mark.parametrize("mode", sorted(set(MODES) - {"silent_after_banner"}))
def test_a_hostile_target_cannot_hang_or_crash_the_gateway(
    mode, processes, cert_wg, honest_target, stub_vault, api, timeout
):
    from .test_ssh_target_cert_auth import connect

    server = HostileSSHServer(mode)
    server.start()
    try:
        user, target = target_on(api, server.port)

        gateway = psutil.Process(cert_wg.process.pid)
        rss_before = gateway.memory_info().rss

        started = time.time()
        code, _ = connect(processes, cert_wg, user, target, timeout)
        elapsed = time.time() - started

        assert server.connections > 0, f"the {mode} server was never reached"
        assert code != 0, f"a session completed against a {mode} server"
        assert elapsed < 60, f"{mode} held the session for {elapsed:.0f}s"

        # An unbounded read shows up here rather than in the exit code.
        growth = gateway.memory_info().rss - rss_before
        assert growth < 256 * 1024 * 1024, (
            f"{mode} grew the gateway by {growth // (1024 * 1024)} MiB"
        )
    finally:
        server.stop()

    # The gateway has to still work: a panic in the client task would show up
    # here and nowhere else.
    user, target = target_on(api, honest_target)
    assert connect(processes, cert_wg, user, target, timeout)[0] == 0


def test_a_target_that_stalls_the_handshake_is_given_up_on(
    processes, cert_wg, honest_target, stub_vault, api, timeout
):
    """A peer that completes TCP, sends a valid identification string and then
    says nothing was previously held forever: russh bounds the length of that
    string but not the time to send what follows, and the inactivity timeout
    only starts once the session loop is running."""
    from .test_ssh_target_cert_auth import start

    server = HostileSSHServer("silent_after_banner")
    server.start()
    try:
        user, target = target_on(api, server.port)
        started = time.time()
        client = start(processes, cert_wg, user, target, "-tt")
        shown = client.communicate(timeout=90)[0].decode(errors="replace")
        code = client.returncode
        elapsed = time.time() - started

        assert server.connections > 0, "the stalling server was never reached"
        assert code != 0
        # Warpgate's own message rather than any non-zero exit: a silent peer
        # and a dropped connection end the session alike, and only one of them
        # is what this test is named for.
        assert "never completed the handshake" in shown, shown[-400:]
        # The handshake has its own 30s bound. Without it this is held for the
        # inactivity timeout instead — five minutes by default, and however long
        # an operator has raised it to.
        assert elapsed < 60, f"the gateway waited {elapsed:.0f}s on a silent handshake"
    finally:
        server.stop()


def test_a_hostile_target_never_gets_a_certificate_it_can_keep(
    processes, cert_wg, honest_target, stub_vault, api, timeout
):
    """A certificate is minted before the target proves anything, so a hostile
    host does receive one — bounded by its two-minute validity and by naming
    only the account on that host. What it must not get is one that is useful
    anywhere else."""
    from .test_ssh_target_cert_auth import connect

    signs_before = len(stub_vault.signs)
    server = HostileSSHServer("garbage_after_banner")
    server.start()
    try:
        user, target = target_on(api, server.port)
        connect(processes, cert_wg, user, target, timeout)
    finally:
        server.stop()

    # Nothing is offered until the transport is up, so a server that never gets
    # that far never sees the certificate at all. Measured as a delta: earlier
    # tests in this module sign against the honest target.
    assert len(stub_vault.signs) == signs_before, (
        "a certificate was issued to a target that never completed a handshake"
    )


def test_a_jump_host_that_never_opens_the_tunnel_is_given_up_on(
    processes, cert_wg, honest_target, stub_vault, api, timeout
):
    """The step that had no bound at all.

    A jump host completes its own handshake and authenticates, so every deadline
    that exists is satisfied — and then the request to open a tunnel to the next
    hop goes unanswered. The next hop's deadline is armed inside
    `wait_for_connection`, which does not run until that tunnel exists, so
    nothing was watching this at all: the hold lasted until the previous hop's
    inactivity timeout, five minutes by default.
    """
    from .stalling_jump_host import PASSWORD, StallingJumpHost
    from .test_ssh_target_cert_auth import USER_PUBLIC_KEY_PATH, connect, start

    jump = StallingJumpHost().start()
    try:
        role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        api.create_public_key_credential(
            user.id,
            sdk.NewPublicKeyCredential(
                label="Public Key",
                openssh_public_key=USER_PUBLIC_KEY_PATH.read_text().strip(),
            ),
        )
        api.add_user_role(user.id, role.id)

        def make(name, port, auth, jump_host=None):
            options = sdk.TargetOptionsTargetSSHOptions(
                kind="Ssh",
                host=TARGET_HOST,
                port=port,
                username="root",
                auth=auth,
            )
            if jump_host is not None:
                options.jump_host = jump_host
            target = api.create_target(
                sdk.TargetDataRequest(name=name, options=sdk.TargetOptions(options))
            )
            api.add_target_role(target.id, role.id)
            return target

        # Password auth for the jump host: the step under test is the tunnel, and
        # negotiating a certificate here would put paramiko's algorithm support
        # in the middle of it.
        stalling = make(
            f"stalling-{uuid4()}",
            jump.port,
            sdk.SSHTargetAuth(
                sdk.SSHTargetAuthSshTargetPasswordAuth(kind="Password", password=PASSWORD)
            ),
        )
        behind = make(
            f"behind-{uuid4()}",
            honest_target,
            sdk.SSHTargetAuth(
                sdk.SSHTargetAuthSshTargetCertificateAuth(
                    kind="Certificate", role=None, allowed_critical_options=[]
                )
            ),
            jump_host=stalling.id,
        )

        # The bound under test is 30s, longer than the timeout the rest of this
        # module wants, so the client is given its own.
        started = time.time()
        client = start(processes, cert_wg, user, behind, "-tt")
        client.communicate(timeout=120)
        code = client.returncode
        elapsed = time.time() - started
        assert jump.tunnel_requested.wait(1), "the tunnel was never requested"
        assert code != 0, "a session completed through a jump host that never answered"
        # The deadline is 30s. Anything near the inactivity timeout means it was
        # not the tunnel step that gave up.
        assert elapsed < 60, f"the jump host held the session for {elapsed:.0f}s"
    finally:
        jump.stop()

    user, target = target_on(api, honest_target)
    assert connect(processes, cert_wg, user, target, timeout)[0] == 0


def test_a_target_that_answers_with_a_host_key_and_then_stalls_is_given_up_on(
    processes, cert_wg, honest_target, stub_vault, api, timeout
):
    """The handshake deadline pauses for a host key decision. It must resume.

    Warpgate stops its own 30s handshake bound while an unknown host key is
    outstanding, because under `Prompt` that wait belongs to a person reading a
    fingerprint rather than to the target. The first version of that pause never
    ended: the deadline was pushed a year out and nothing brought it back. The
    verification mode is not even known at that point in the code — it is read
    later — so `AutoAccept`, which answers in microseconds with nobody waiting,
    cancelled the bound just as thoroughly.

    This server sends the key exchange reply carrying its host key and then
    nothing at all, so the transport never completes. The key is unknown — it is
    generated per instance — and the mode is set to `AutoAccept` below so the
    answer comes straight back: that is what lifts the pause, and the remaining
    handshake is the target's again from there, which is the moment the bound
    has to come back.

    Measured, not assumed. With the resume disabled and the mode left at its
    default the test still passed, because under `Prompt` the answer never
    arrives, the pause is never lifted, and the line under test never executes.
    The verifier reported the guard as undiscriminated for exactly that reason.
    """
    from .stalling_host_key_server import StallingHostKeyServer
    from .test_ssh_target_cert_auth import connect, start

    # Set explicitly, and this is the whole reason the test was worthless before.
    # The default is `Prompt`, which waits for a human on a stdin the harness has
    # closed — so the answer never came back, the pause was never lifted, and the
    # line under test never ran at all. The mutation was inert and the test
    # passed either way. The docstring said "the fixture accepts it
    # automatically"; nothing in the fixture did.
    api.update_parameters(
        sdk.ParameterUpdate(
            ssh_host_key_verification=sdk.SshHostKeyVerificationMode.AUTOACCEPT
        )
    )

    server = StallingHostKeyServer()
    server.start()
    try:
        user, target = target_on(api, server.port)
        started = time.time()
        client = start(processes, cert_wg, user, target, "-tt")
        shown = client.communicate(timeout=180)[0].decode(errors="replace")
        elapsed = time.time() - started

        assert server.connections > 0, "the stalling server was never reached"
        assert server.key_delivered.wait(1), (
            "the server never got as far as sending its host key, so the pause "
            "under test was never entered"
        )
        assert client.returncode != 0

        # Warpgate's own message, not merely a dropped connection: the target is
        # unreachable for several reasons here and only one of them is the one
        # being measured.
        assert "never completed the handshake" in shown, shown[-400:]

        # The bound is 30s, and the inactivity timeout it must not fall through
        # to is 300s. Anything past 90s means the pause never ended.
        assert elapsed < 90, (
            f"the gateway waited {elapsed:.0f}s after the host key was accepted"
        )
    finally:
        server.stop()

    user, target = target_on(api, honest_target)
    assert connect(processes, cert_wg, user, target, timeout)[0] == 0


def test_break_glass_user_creation_does_not_depend_on_vault(
    processes: ProcessManager, ctx, stub_vault
):
    """A Vault outage must not lock the door it is needed to open.

    `create-user` and `recover-access` build their services through
    `Services::new_without_vault`, so a `vault:` section that cannot even be
    constructed does not stop an operator making an account. Without that, a
    misconfigured or unreachable Vault takes down every target *and* the command
    for getting back in — including the one target you would fix Vault from.

    The mount here contains a slash, which `validate_segment` refuses, so
    `Services::new` fails outright before any network call. That is deliberate:
    it fails the same way with Vault up or down, so the test needs no outage and
    no timeout.

    `recover-access` takes the same path but asserts an interactive terminal
    first, so it cannot be driven from a harness; `create-user` is the same
    branch and is the one pinned here.
    """
    import subprocess

    import yaml

    from .conftest import binary_path, cargo_root

    wg = processes.start_wg()
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    config = yaml.safe_load(wg.config_path.open())
    wg.process.kill()
    wg.process.wait()

    config["vault"] = {
        "address": stub_vault.url,
        "ca_bundle": stub_vault.ca_bundle,
        "default_role": "warpgate",
        # Rejected by `validate_segment`: a mount is one path segment.
        "mount": "ssh/../../sys",
        "auth": {"kind": "kubernetes", "role": "warpgate", "token_path": "/dev/null"},
    }
    broken = wg.config_path.parent / f"break-glass-{uuid4()}.yaml"
    with broken.open("w") as f:
        yaml.safe_dump(config, f)

    username = f"locked-out-{uuid4()}"
    result = subprocess.run(
        [
            str(cargo_root / binary_path),
            "--config",
            str(broken),
            "create-user",
            username,
            "--password",
            "not-a-real-password",
        ],
        capture_output=True,
        timeout=120,
    )
    output = (result.stdout + result.stderr).decode(errors="replace")

    # Naming the failure, because "non-zero exit" would also pass if the binary
    # were missing or the config unparseable — neither of which is this guard.
    assert "invalid Vault role or mount name" not in output, output[-600:]
    assert result.returncode == 0, output[-600:]
