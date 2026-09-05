"""End-to-end evidence for what a connected user is shown in the terminal.

The unit tests around `shown_in_the_terminal` and `client_message` exercise
those functions directly. This goes one level out: a real warpgate, a real
`ssh` client, a real target that cannot be reached, and the bytes that
actually arrive on the terminal.

A PTY is forced with `-tt` on purpose. `emit_pty_output` writes only to
channels that carry a PTY, so a plain `ssh host command` never sees any of
this -- the leg under test is the interactive one.

The browser leg is deliberately absent, and not for want of trying. Its
`RCEvent::ConnectionError` arm cannot be observed end to end:

  * for a connect-time failure the web-SSH session is torn down before any
    websocket can attach -- `GET` on the session id returns 404 immediately
    after the `POST` that created it returned 201, so the message the manager
    produces (it does; the log carries it) has nobody to reach;
  * a mid-session target death does not produce `ConnectionError` at all. The
    connection was established, so the death arrives as
    `Drop for ClientHandler` -> `State(Disconnected)`.

Attaching a browser to a slow-failing target would close that window, but the
window is the test's premise rather than the product's behaviour. The arm
keeps its unit test; this file covers the leg a stock `ssh` client reaches,
which is the one Warpgate's contract is about.
"""

import subprocess
import time
from pathlib import Path
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .util import alloc_port, wait_port


def _start_wg_with_log(processes: ProcessManager, tmp_path: Path):
    """Start warpgate with its own log captured to a file."""
    log_path = tmp_path / "warpgate.log"
    log_file = log_path.open("w")
    wg = processes.start_wg(stdout=log_file, stderr=subprocess.STDOUT)
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    wait_port(wg.ssh_port, for_process=wg.process)
    return wg, log_path


def _log_after(log_path: Path, needle: str, deadline: float = 5.0) -> str:
    end = time.time() + deadline
    text = ""
    while time.time() < end:
        text = log_path.read_text(errors="replace")
        if needle in text:
            break
        time.sleep(0.2)
    return text


def test_the_terminal_is_told_what_happened_not_what_the_error_said(
    processes: ProcessManager, tmp_path: Path, timeout
):
    """A target Warpgate cannot connect to, reached over a real SSH session.

    The port is allocated and then deliberately left unbound, so the outbound
    connection fails with an `std::io::Error` -- the `#[error(transparent)]`
    variant of `ConnectionError`, whose `Display` is whatever the operating
    system said. That is the text this test is about.
    """
    wg, log_path = _start_wg_with_log(processes, tmp_path)

    dead_port = alloc_port()

    url = f"https://localhost:{wg.http_port}"
    with admin_client(url) as api:
        role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        api.create_password_credential(
            user.id, sdk.NewPasswordCredential(password="123")
        )
        api.add_user_role(user.id, role.id)
        target = api.create_target(
            sdk.TargetDataRequest(
                name=f"dead-{uuid4()}",
                options=sdk.TargetOptions(
                    sdk.TargetOptionsTargetSSHOptions(
                        kind="Ssh",
                        host="localhost",
                        port=dead_port,
                        username="root",
                        auth=sdk.SSHTargetAuth(
                            sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                        ),
                    )
                ),
            )
        )
        api.add_target_role(target.id, role.id)

    client = processes.start_ssh_client(
        f"{user.username}:{target.name}@localhost",
        "-p",
        str(wg.ssh_port),
        "-i",
        "/dev/null",
        "-o",
        "PreferredAuthentications=password",
        # Force a PTY: `emit_pty_output` writes only to channels that have one.
        "-tt",
        password="123",
        stderr=subprocess.STDOUT,
    )
    terminal = client.communicate(timeout=timeout)[0].decode(errors="replace")

    # Non-vacuity, both halves: the session really did reach the arm under
    # test, rather than failing earlier for some unrelated reason.
    assert "Warpgate:" in terminal, (
        f"warpgate never wrote to the terminal at all: {terminal!r}"
    )
    assert "Target connection failed" in terminal, (
        f"the target-connection arm never ran: {terminal!r}"
    )

    for fragment in ("os error", "refused", "Connection reset", "No route"):
        assert fragment.lower() not in terminal.lower(), (
            f"the operating system's own words reached the terminal "
            f"({fragment!r}): {terminal!r}"
        )
    assert "SSH protocol error" in terminal, (
        f"the sanitised phrase is missing, so something else was shown: "
        f"{terminal!r}"
    )

    # The other half: the real reason has to still exist somewhere.
    log = _log_after(log_path, "Target connection failed")
    assert "Target connection failed" in log, (
        "the failure was not logged at all -- the detail was discarded rather "
        "than relocated"
    )
    reason_logged = any(
        marker in log for marker in ("os error", "refused", "Connection refused")
    )
    assert reason_logged, (
        "the operating system's reason did not survive into the log either; "
        "an operator has nothing to work from"
    )
