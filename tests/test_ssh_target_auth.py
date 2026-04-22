from pathlib import Path
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port

USER_PUBLIC_KEY_PATH = Path("ssh-keys/id_ed25519.pub")
USER_PRIVATE_KEY_PATH = "ssh-keys/id_ed25519"


class Test:
    @staticmethod
    def _create_user_role_and_target(api, ssh_port, username: str, auth):
        role = api.create_role(
            sdk.RoleDataRequest(name=f"role-{uuid4()}"),
        )
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        api.create_public_key_credential(
            user.id,
            sdk.NewPublicKeyCredential(
                label="Public Key",
                openssh_public_key=USER_PUBLIC_KEY_PATH.read_text().strip(),
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
                        username=username,
                        auth=sdk.SSHTargetAuth(auth),
                    )
                ),
            )
        )
        api.add_target_role(ssh_target.id, role.id)
        return user, ssh_target

    @staticmethod
    def _run_ssh_ls(
        processes: ProcessManager,
        shared_wg: WarpgateProcess,
        user,
        ssh_target,
    ):
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-o",
            f"IdentityFile={USER_PRIVATE_KEY_PATH}",
            "-o",
            "PreferredAuthentications=publickey",
            "ls",
            "/bin/sh",
        )
        return ssh_client

    def test_password(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        ssh_port = processes.start_ssh_server()

        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, ssh_target = self._create_user_role_and_target(
                api,
                ssh_port,
                username="foo",
                auth=sdk.SSHTargetAuthSshTargetPasswordAuth(
                    kind="Password",
                    password="bar",
                ),
            )

        ssh_client = self._run_ssh_ls(
            processes,
            shared_wg,
            user,
            ssh_target,
        )
        assert ssh_client.communicate(timeout=timeout)[0] == b"/bin/sh\n"
        assert ssh_client.returncode == 0

    def test_certificate(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        ssh_port = processes.start_ssh_server(
            trusted_ca=[wg_c_ed25519_pubkey.read_text()]
        )

        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, ssh_target = self._create_user_role_and_target(
                api,
                ssh_port,
                username="root",
                auth=sdk.SSHTargetAuthSshTargetCertificateAuth(kind="Certificate"),
            )

        ssh_client = self._run_ssh_ls(
            processes,
            shared_wg,
            user,
            ssh_target,
        )
        assert ssh_client.communicate(timeout=timeout)[0] == b"/bin/sh\n"
        assert ssh_client.returncode == 0

    def test_none(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        ssh_port = processes.start_ssh_server()

        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, ssh_target = self._create_user_role_and_target(
                api,
                ssh_port,
                username="root",
                auth=sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey"),
            )

        ssh_client = self._run_ssh_ls(
            processes,
            shared_wg,
            user,
            ssh_target,
        )
        assert ssh_client.communicate(timeout=timeout)[0] == b""
        assert ssh_client.returncode != 0
