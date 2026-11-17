from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


class Test:
    """A target with `interactive` auth stores no credentials: once Warpgate
    has accepted the user, it asks them for the target's password through an
    extra keyboard-interactive round and passes it on."""

    def test(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        ssh_port = processes.start_ssh_server(root_password="hunter2")
        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
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
            ssh_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    require_approval=False,
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
                                sdk.SSHTargetAuthSshTargetInteractiveAuth(
                                    kind="Interactive"
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(ssh_target.id, role.id)

        def connect(target_password):
            return processes.start_ssh_client(
                f"{user.username}:{ssh_target.name}@localhost",
                "-p",
                str(shared_wg.ssh_port),
                "-o",
                "IdentityFile=ssh-keys/id_ed25519",
                "-o",
                "PreferredAuthentications=publickey,keyboard-interactive",
                "ls",
                "/bin/sh",
                # Warpgate itself is satisfied by the key, so the only prompt
                # is the one for the target's password.
                password=target_password,
            )

        ssh_client = connect("hunter2")
        assert ssh_client.communicate(timeout=timeout)[0] == b"/bin/sh\n"
        assert ssh_client.returncode == 0

        ssh_client = connect("wrong-password")
        assert ssh_client.communicate(timeout=timeout)[0] == b""
        assert ssh_client.returncode != 0
