"""What the client is told when the gateway closes an idle session.

The gateway prints `Closing the session due to inactivity` and disconnects in
the next two statements (`server/session.rs`, the inactivity arm of the event
loop). Both go through the same outbound queue, and the disconnect ends the SSH
session as soon as the client processes it -- so whether the user ever learns
why the session ended depends on the client draining the message first.

`test_ssh_proto.py::Test::test_connection_error` looks like it covers a
disconnect reason and does not: it asserts `returncode != 0` without waiting
for the client, so it reads `None != 0` and passes while the client is still
running, and it never looks at what the client was shown.
"""

import pytest

from .conftest import ProcessManager, WarpgateProcess
from .test_ssh_proto import setup_user_and_target
from .util import wait_port


@pytest.fixture
def impatient_wg(processes: ProcessManager):
    """Its own gateway: the inactivity timeout under test defaults to minutes."""
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

    # No input is sent, so the session sits idle until the gateway gives up on
    # it. `communicate` also waits for the client, which is what makes the exit
    # code below mean anything.
    shown = client.communicate(timeout=60)[0].decode(errors="replace")

    # 255 rather than merely non-None: the client has to have been disconnected
    # by the peer, not have exited for some reason of its own.
    assert client.returncode == 255, client.returncode
    # The whole phrase, not the word: a target MOTD or hostname carrying
    # "inactivity" would let this pass while the notice was dropped.
    assert "Closing the session due to inactivity" in shown, repr(shown[-400:])
