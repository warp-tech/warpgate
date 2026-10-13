"""A session closed for inactivity tells the client why.

The notice and the connection-level disconnect leave in that order; a client
that reads both in one batch exits without printing the notice, so the
disconnect has to follow after a gap.
"""

import pytest

from .conftest import ProcessManager, WarpgateProcess
from .test_ssh_proto import setup_user_and_target
from .util import wait_port


@pytest.fixture
def impatient_wg(processes: ProcessManager):
    wg = processes.start_wg(config_patch={"ssh": {"inactivity_timeout": "5s"}})
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    wait_port(wg.ssh_port, for_process=wg.process)
    yield wg


def test_an_idle_session_tells_the_client_why_it_was_closed(
    processes: ProcessManager,
    wg_c_ed25519_pubkey,
    impatient_wg: WarpgateProcess,
):
    user, ssh_target = setup_user_and_target(
        processes, impatient_wg, wg_c_ed25519_pubkey
    )
    client = processes.start_ssh_client(
        f"{user.username}:{ssh_target.name}@localhost",
        "-p",
        str(impatient_wg.ssh_port),
        "-tt",
        "-i",
        "/dev/null",
        "-o",
        "PreferredAuthentications=password",
        password="123",
    )

    # No input: the session idles until the gateway closes it.
    shown = client.communicate(timeout=60)[0].decode(errors="replace")

    assert client.returncode == 255, client.returncode
    assert "Closing the session due to inactivity" in shown, repr(shown[-400:])
