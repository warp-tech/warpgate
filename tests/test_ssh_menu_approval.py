from pathlib import Path
import subprocess
import threading
import time
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .approval_util import wait_for_pending_approval
from .util import wait_port


def _create_menu_target(api, ssh_port: int, require_approval: bool):
    role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
    user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
    api.create_public_key_credential(
        user.id,
        sdk.NewPublicKeyCredential(
            label="Public Key",
            openssh_public_key=open("ssh-keys/id_ed25519.pub").read().strip(),
        ),
    )
    api.add_user_role(user.id, role.id)
    request = sdk.TargetDataRequest(
        name=f"ssh-{uuid4()}",
        require_approval=require_approval,
        ticket_requests_disabled=False,
        ticket_require_approval=False,
        options=sdk.TargetOptions(
            sdk.TargetOptionsTargetSSHOptions(
                kind="Ssh",
                allow_insecure_algos=False,
                host="localhost",
                port=ssh_port,
                username="root",
                auth=sdk.SSHTargetAuth(
                    sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                ),
            )
        ),
    )
    target = api.create_target(request)
    api.add_target_role(target.id, role.id)
    return user, target, request


def _start_menu_client(processes: ProcessManager, wg: WarpgateProcess, username: str):
    # No target in the selector -> the menu. -tt: force a pty even though our
    # stdin is a pipe, otherwise the menu never starts.
    return processes.start_ssh_client(
        "-tt",
        f"{username}@localhost",
        "-p",
        str(wg.ssh_port),
        "-o",
        "IdentityFile=ssh-keys/id_ed25519",
        stderr=subprocess.PIPE,
    )


def _approve(url: str, approval):
    with admin_client(url) as api:
        api.approve_session(
            approval.id,
            sdk.ApproveSessionRequest(scope=sdk.ApprovalScope.ONCE, target=approval.target),
        )


class Test:
    def test_menu_selection_is_held_for_approval(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # Connecting without a target goes through the interactive menu, so the
        # target is only known *after* authentication and the approval
        # requirement can't be part of the credential policy. The choice itself
        # must be held instead — otherwise `require_approval` is bypassable by
        # anyone who uses the menu.
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, target, _ = _create_menu_target(api, ssh_port, require_approval=True)

        client = _start_menu_client(processes, shared_wg, user.username)

        # Enter selects the highlighted (only) target. The menu may not have
        # rendered by the time we get here, so retry the keypress.
        approval = None
        for _ in range(5):
            client.stdin.write(b"\r")
            client.stdin.flush()
            with admin_client(url) as api:
                try:
                    approval = wait_for_pending_approval(
                        api, target.name, user.username, deadline=3
                    )
                    break
                except AssertionError:
                    continue
        assert approval, "menu selection was not held for approval"

        _approve(url, approval)

        # Approved: the session connects to the target and runs a command.
        output = client.communicate(b"echo approved-ok\nexit\n", timeout=timeout)[0]
        assert b"approved-ok" in output

    def test_approval_enabled_while_menu_open_is_enforced(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, target, request = _create_menu_target(
                api, ssh_port, require_approval=False
            )

        client = _start_menu_client(processes, shared_wg, user.username)
        output = bytearray()

        def read():
            while chunk := client.stdout.read1(4096):
                output.extend(chunk)

        reader = threading.Thread(target=read, daemon=True)
        reader.start()

        # The menu lists the target only once it has been built from the DB.
        deadline = time.time() + timeout
        while target.name.encode() not in output:
            assert time.time() < deadline, "menu never rendered the target"
            time.sleep(0.1)

        request.require_approval = True
        with admin_client(url) as api:
            api.update_target(target.id, request)

        client.stdin.write(b"\r")
        client.stdin.flush()
        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)

        _approve(url, approval)

        client.stdin.write(b"echo approved-ok\nexit\n")
        client.stdin.close()
        client.wait(timeout=timeout)
        reader.join(timeout=timeout)
        assert b"approved-ok" in output
