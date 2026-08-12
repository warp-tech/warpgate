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
from .conftest import ProcessManager
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
            # Short, so a handshake that never finishes is measurable inside a
            # test rather than only in production.
            
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
        # The configured inactivity timeout is 8s; the assertion is that the
        # handshake is bounded by something at all.
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
