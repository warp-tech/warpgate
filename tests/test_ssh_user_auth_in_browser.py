import aiohttp
import pytest
from pathlib import Path
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


class Test:
    # When include_pk is False, we're testing for
    # https://github.com/warp-tech/warpgate/issues/972
    # where the SSH server fails to offer keyboard-interactive authentication
    # when no OTP credential is present.
    @pytest.mark.parametrize("include_pk", [True, False])
    @pytest.mark.asyncio
    async def test(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
        include_pk: bool,
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
            if include_pk:
                api.create_public_key_credential(
                    user.id,
                    sdk.NewPublicKeyCredential(
                        label="Public Key",
                        openssh_public_key=open("ssh-keys/id_ed25519.pub").read().strip()
                    ),
                )
            api.add_user_role(user.id, role.id, sdk.AddUserRoleRequest(expires_at=None))
            api.update_user(
                user.id,
                sdk.UserDataRequest(
                    username=user.username,
                    credential_policy=sdk.UserRequireCredentialsPolicy(
                        ssh=[sdk.CredentialKind.WEBUSERAPPROVAL] if not include_pk else [
                            sdk.CredentialKind.PUBLICKEY,
                            sdk.CredentialKind.WEBUSERAPPROVAL,
                        ],
                    ),
                ),
            )
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

        session = aiohttp.ClientSession()
        headers = {"Host": f"localhost:{shared_wg.http_port}"}

        await session.post(
            f"{url}/@warpgate/api/auth/login",
            json={
                "username": user.username,
                "password": "123",
            },
            headers=headers,
            ssl=False,
        )
        ws = await session.ws_connect(url.replace('https:', 'wss:') + '/@warpgate/api/auth/web-auth-requests/stream', ssl=False)

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-o",
            "IdentityFile=ssh-keys/id_ed25519",
            "ls",
            "/bin/sh",
        )

        msg = await ws.receive(5)

        auth_id = msg.data
        auth_state = await (await session.get(f'{url}/@warpgate/api/auth/state/{auth_id}', ssl=False)).json()
        assert auth_state['protocol'] == 'SSH'
        assert auth_state['state'] == 'WebUserApprovalNeeded'
        r = await session.post(f'{url}/@warpgate/api/auth/state/{auth_id}/approve', ssl=False)
        assert r.status == 200

        ssh_client.stdin.write(b"\r\n")

        assert ssh_client.communicate(timeout=timeout)[0] == b"/bin/sh\n"
        assert ssh_client.returncode == 0
