from pathlib import Path
import subprocess
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .test_postgres_admin_approval import _wait_for_pending_approval
from .util import wait_port


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
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            # Public key rather than password: sshpass drives ssh through its
            # own pty, which would swallow the keypress we send to the menu.
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

        # No target in the selector -> the menu.
        client = processes.start_ssh_client(
            # -tt: force a pty even though our stdin is a pipe, otherwise the
            # menu never starts.
            "-tt",
            f"{user.username}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-o",
            "IdentityFile=ssh-keys/id_ed25519",
            stderr=subprocess.PIPE,
        )

        # Enter selects the highlighted (only) target. The menu may not have
        # rendered by the time we get here, so retry the keypress.
        approval = None
        for _ in range(5):
            client.stdin.write(b"\r")
            client.stdin.flush()
            with admin_client(url) as api:
                try:
                    approval = _wait_for_pending_approval(
                        api, target.name, user.username, deadline=3
                    )
                    break
                except AssertionError:
                    continue
        assert approval, "menu selection was not held for approval"

        with admin_client(url) as api:
            api.approve_session(approval.id, sdk.SessionApprovalScope.ONCE)

        # Approved: the session connects to the target and runs a command.
        output = client.communicate(b"echo approved-ok\nexit\n", timeout=timeout)[0]
        assert b"approved-ok" in output
