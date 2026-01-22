from asyncio import subprocess
from base64 import b64decode
from uuid import uuid4
import pyotp
import pytest
from pathlib import Path
from textwrap import dedent

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


class Test:
    def test_otp(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        otp_key_base32: str,
        otp_key_base64: str,
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
                    openssh_public_key=open("ssh-keys/id_ed25519.pub").read().strip(),
                ),
            )
            api.create_otp_credential(
                user.id,
                sdk.NewOtpCredential(
                    secret_key=list(b64decode(otp_key_base64)),
                ),
            )
            api.update_user(
                user.id,
                sdk.UserDataRequest(
                    username=user.username,
                    credential_policy=sdk.UserRequireCredentialsPolicy(
                        ssh=["PublicKey", "Totp"],
                    ),
                ),
            )
            api.add_user_role(user.id, role.id, sdk.AddUserRoleRequest(expires_at=None))
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

        totp = pyotp.TOTP(otp_key_base32)

        script = dedent(
            f"""
            set timeout {timeout - 5}

            spawn ssh {user.username}:{ssh_target.name}@localhost -p {shared_wg.ssh_port} -o StrictHostKeychecking=no -o UserKnownHostsFile=/dev/null  -o IdentitiesOnly=yes -o IdentityFile=ssh-keys/id_ed25519 -o PreferredAuthentications=publickey,keyboard-interactive ls /bin/sh

            expect "Two-factor authentication"
            sleep 0.5
            send "{totp.now()}\\r"

            expect {{
                "/bin/sh"  {{ exit 0; }}
                eof {{ exit 1; }}
            }}
            """
        )

        ssh_client = processes.start(
            ["expect"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        output, stderr = ssh_client.communicate(script.encode(), timeout=timeout)
        assert ssh_client.returncode == 0, output + stderr

        script = dedent(
            f"""
            set timeout {timeout - 5}

            spawn ssh {user.username}:{ssh_target.name}@localhost -p {[shared_wg.ssh_port]} -o StrictHostKeychecking=no -o UserKnownHostsFile=/dev/null  -o IdentitiesOnly=yes -o IdentityFile=ssh-keys/id_ed25519 -o PreferredAuthentications=publickey,keyboard-interactive ls /bin/sh

            expect "Two-factor authentication"
            sleep 0.5
            send "12345678\\r"

            expect {{
                "/bin/sh"  {{ exit 0; }}
                "Two-factor authentication" {{ exit 1; }}
                eof {{ exit 1; }}
            }}
            """
        )

        ssh_client = processes.start(
            ["expect"], stdin=subprocess.PIPE, stdout=subprocess.PIPE
        )

        output = ssh_client.communicate(script.encode(), timeout=timeout)[0]
        assert ssh_client.returncode != 0, output
