from pathlib import Path
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


class Test:
    def test(
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
            role = api.create_role(
                sdk.RoleDataRequest(name=f"role-{uuid4()}"),
            )
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
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
                                    kind="PublicKey"
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(ssh_target.id, role.id)

            secret = api.create_ticket(
                sdk.CreateTicketRequest(
                    target_name=ssh_target.name,
                    username=user.username,
                )
            ).secret

            ssh_client = processes.start_ssh_client(
                f"ticket-{secret}@localhost",
                "-p",
                str(shared_wg.ssh_port),
                "-i",
                "/dev/null",
                "-o",
                "PreferredAuthentications=password",
                "ls",
                "/bin/sh",
                password="123",
            )
            assert ssh_client.communicate(timeout=timeout)[0] == b"/bin/sh\n"
            assert ssh_client.returncode == 0
