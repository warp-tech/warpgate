from asyncio import subprocess
from base64 import b64decode
from uuid import uuid4
import pyotp
from pathlib import Path
from textwrap import dedent

from .api_client import (
    api_add_role_to_target,
    api_add_role_to_user,
    api_admin_session,
    api_create_role,
    api_create_target,
    api_create_user,
)
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
        with api_admin_session(url) as session:
            role = api_create_role(url, session, {"name": f"role-{uuid4()}"})
            user = api_create_user(
                url,
                session,
                {
                    "username": f"user-{uuid4()}",
                    "credentials": [
                        {
                            "kind": "PublicKey",
                            "key": open("ssh-keys/id_ed25519.pub").read().strip(),
                        },
                        {
                            "kind": "Totp",
                            "key": list(b64decode(otp_key_base64)),
                        },
                    ],
                    "credential_policy": {
                        "ssh": ["PublicKey", "Totp"],
                    },
                },
            )
            api_add_role_to_user(url, session, user["id"], role["id"])
            ssh_target = api_create_target(
                url,
                session,
                {
                    "name": f"ssh-{uuid4()}",
                    "options": {
                        "kind": "Ssh",
                        "host": "localhost",
                        "port": ssh_port,
                        "username": "root",
                        "auth": {"kind": "PublicKey"},
                    },
                },
            )
            api_add_role_to_target(url, session, ssh_target["id"], role["id"])

        totp = pyotp.TOTP(otp_key_base32)

        script = dedent(
            f"""
            set timeout {timeout - 5}

            spawn ssh {user["username"]}:{ssh_target["name"]}@localhost -p {shared_wg.ssh_port} -o StrictHostKeychecking=no -o UserKnownHostsFile=/dev/null  -o IdentitiesOnly=yes -o IdentityFile=ssh-keys/id_ed25519 -o PreferredAuthentications=publickey,keyboard-interactive ls /bin/sh

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

            spawn ssh {user["username"]}:{ssh_target["name"]}@localhost -p {[shared_wg.ssh_port]} -o StrictHostKeychecking=no -o UserKnownHostsFile=/dev/null  -o IdentitiesOnly=yes -o IdentityFile=ssh-keys/id_ed25519 -o PreferredAuthentications=publickey,keyboard-interactive ls /bin/sh

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
