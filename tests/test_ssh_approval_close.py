from pathlib import Path
import subprocess
import time
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .test_postgres_admin_approval import _wait_for_pending_approval
from .util import wait_port


class Test:
    def test_client_disconnect_clears_the_pending_approval(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        shared_wg: WarpgateProcess,
    ):
        # The hold runs off the session event loop, so russh keeps reading the
        # socket and notices the client leaving. Without that the request would
        # sit in the admin inbox until the approval window elapsed, and approving
        # it would stamp a grace-period bypass for a client that had gone.
        url, user, target = _held_ssh_target(processes, wg_c_ed25519_pubkey, shared_wg)
        client = _connect_held(processes, shared_wg, user, target)

        with admin_client(url) as api:
            _wait_for_pending_approval(api, target.name, user.username)

        client.kill()
        client.wait(timeout=10)
        _assert_request_disappears(url, user, target)

    def test_target_is_not_reached_before_approval(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # The whole point of the gate: nothing may reach the target until an
        # administrator says so. The hold runs off the session event loop, so
        # this is the assertion that keeps `connect_remote` behind it.
        url, user, target = _held_ssh_target(processes, wg_c_ed25519_pubkey, shared_wg)
        client = _connect_held(
            processes, shared_wg, user, target, "echo", "gate-marker"
        )

        with admin_client(url) as api:
            approval = _wait_for_pending_approval(api, target.name, user.username)

            # A connection that slipped past the gate would have run the command
            # and exited by now.
            time.sleep(2)
            assert client.poll() is None, "session connected before approval"

            api.approve_session(approval.id, sdk.SessionApprovalScope.ONCE)

        assert b"gate-marker" in client.communicate(timeout=timeout)[0]

    def test_admin_can_close_a_session_waiting_for_approval(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        shared_wg: WarpgateProcess,
    ):
        # The close command arrives on the session-handle channel, which is
        # independent of the connection — so an administrator can get rid of a
        # held session without resolving it or waiting out the whole window.
        url, user, target = _held_ssh_target(processes, wg_c_ed25519_pubkey, shared_wg)
        client = _connect_held(processes, shared_wg, user, target)

        with admin_client(url) as api:
            approval = _wait_for_pending_approval(api, target.name, user.username)
            api.close_session(approval.id)

        _assert_request_disappears(url, user, target)
        assert client.wait(timeout=10) != 0


def _held_ssh_target(processes, wg_c_ed25519_pubkey, shared_wg):
    """A password user and an SSH target gated by JIT admin approval."""
    ssh_port = processes.start_ssh_server(trusted_keys=[wg_c_ed25519_pubkey.read_text()])
    wait_port(ssh_port)

    url = f"https://localhost:{shared_wg.http_port}"
    with admin_client(url) as api:
        role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        # Public key rather than password: sshpass retries on its own, which
        # shows up as spurious failed-login attempts under a loaded suite.
        api.create_public_key_credential(
            user.id,
            sdk.NewPublicKeyCredential(
                label="Public Key",
                openssh_public_key=open("ssh-keys/id_ed25519.pub").read().strip(),
            ),
        )
        api.add_user_role(user.id, role.id)
        target = api.create_target(
            sdk.TargetDataRequest(
                name=f"ssh-{uuid4()}",
                require_approval=True,
                options=sdk.TargetOptions(
                    sdk.TargetOptionsTargetSSHOptions(
                        kind="Ssh",
                        host="localhost",
                        port=ssh_port,
                        username="root",
                        auth=sdk.SSHTargetAuth(
                            sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                        ),
                    )
                ),
            )
        )
        api.add_target_role(target.id, role.id)
    return url, user, target


def _connect_held(processes, shared_wg, user, target, *command):
    """Start ssh; it authenticates, then waits for the approval."""
    return processes.start_ssh_client(
        f"{user.username}#{target.name}@localhost",
        "-p",
        str(shared_wg.ssh_port),
        "-o",
        "IdentityFile=ssh-keys/id_ed25519",
        *command,
        stderr=subprocess.PIPE,
    )


def _assert_request_disappears(url, user, target):
    """The request must clear on its own — no admin decision, and well inside
    the approval window."""
    with admin_client(url) as api:
        for _ in range(40):
            pending = [
                a
                for a in api.get_session_approvals()
                if a.target == target.name and a.username == user.username
            ]
            if not pending:
                return
            time.sleep(0.25)
    raise AssertionError("approval request outlived the session")
