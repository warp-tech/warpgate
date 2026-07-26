from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


class Test:
    def test_generate_assign_authenticate(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        """Generate a client key via the API, assign it to an SSH target, and
        verify Warpgate authenticates to the target with that specific key."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            key = api.generate_ssh_own_key(
                sdk.GenerateSSHClientKeyRequest(
                    label=f"key-{uuid4()}",
                    kind=sdk.SSHClientKeyKind.ED25519,
                )
            )
            assert key.is_default is False
            assert key.public_key.startswith("ssh-ed25519 ")

        # The target server trusts only the generated key, so authentication
        # succeeds only if the target's key_id selection is honoured.
        ssh_port = processes.start_ssh_server(trusted_keys=[key.public_key])
        wait_port(ssh_port)

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
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            host="localhost",
                            port=ssh_port,
                            username="root",
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(
                                    kind="PublicKey",
                                    key_id=key.id,
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(ssh_target.id, role.id)

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-o",
            "IdentityFile=ssh-keys/id_ed25519",
            "-o",
            "PreferredAuthentications=publickey",
            "ls",
            "/bin/sh",
        )
        output, _ = ssh_client.communicate(timeout=timeout)
        assert output == b"/bin/sh\n"
        assert ssh_client.returncode == 0
