from pathlib import Path
from uuid import uuid4

import pytest
import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


class Test:
    @pytest.mark.parametrize("self_service", [False, True], ids=["admin", "profile-comment"])
    def test_ed25519(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
        self_service,
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
            if self_service:
                api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
                public_key = " ".join(Path("ssh-keys/id_ed25519.pub").read_text().split()[:2])
                with requests.Session() as session:
                    session.verify = False
                    response = session.post(
                        f"{url}/@warpgate/api/auth/login",
                        json={"username": user.username, "password": "123"},
                    )
                    assert response.status_code == 201, response.text
                    response = session.post(
                        f"{url}/@warpgate/api/profile/credentials/public-keys",
                        json={"label": "Public Key", "openssh_public_key": f"{public_key} user@host"},
                    )
                    assert response.status_code == 201, response.text
                credentials = api.get_public_key_credentials(user.id)
                assert credentials[0].openssh_public_key == public_key
            else:
                api.create_public_key_credential(
                    user.id,
                    sdk.NewPublicKeyCredential(
                        label="Public Key",
                        openssh_public_key=open("ssh-keys/id_ed25519.pub").read().strip()
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
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(
                                    kind="PublicKey"
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
            # 'sh', '-c', '"ls /bin/sh;sleep 1"',
            "ls",
            "/bin/sh",
        )
        assert ssh_client.communicate(timeout=timeout)[0] == b"/bin/sh\n"
        assert ssh_client.returncode == 0

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-o",
            "IdentityFile=ssh-keys/id_rsa",
            "-o",
            "PreferredAuthentications=publickey",
            "ls",
            "/bin/sh",
        )
        assert ssh_client.communicate(timeout=timeout)[0] == b""
        assert ssh_client.returncode != 0

    def test_rsa(
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
            api.create_public_key_credential(
                user.id,
                sdk.NewPublicKeyCredential(
                    label="Public Key",
                    openssh_public_key=open("ssh-keys/id_rsa.pub").read().strip()
                ),
            )
            api.add_user_role(user.id, role.id)
            ssh_target = api.create_target(sdk.TargetDataRequest(
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
                            sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                        ),
                    )
                ),
            ))
            api.add_target_role(ssh_target.id, role.id)

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-v",
            "-p",
            str(shared_wg.ssh_port),
            "-o",
            "IdentityFile=ssh-keys/id_rsa",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "PubkeyAcceptedKeyTypes=+ssh-rsa",
            "ls",
            "/bin/sh",
        )
        assert ssh_client.communicate(timeout=timeout)[0] == b"/bin/sh\n"
        assert ssh_client.returncode == 0

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-o",
            "IdentityFile=ssh-keys/id_ed25519",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "PubkeyAcceptedKeyTypes=+ssh-rsa",
            "ls",
            "/bin/sh",
        )
        assert ssh_client.communicate(timeout=timeout)[0] == b""
        assert ssh_client.returncode != 0
