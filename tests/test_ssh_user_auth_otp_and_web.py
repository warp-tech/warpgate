import asyncio
import subprocess
import tempfile
from base64 import b64decode
from pathlib import Path
from textwrap import dedent
from uuid import uuid4

import aiohttp
import pyotp
import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


class Test:
    @pytest.mark.asyncio
    async def test_otp_and_web_auth(
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
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
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
                sdk.NewOtpCredential(secret_key=list(b64decode(otp_key_base64))),
            )
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.update_user(
                user.id,
                sdk.UserDataRequest(
                    username=user.username,
                    credential_policy=sdk.UserRequireCredentialsPolicy(
                        ssh=[
                            sdk.CredentialKind.PUBLICKEY,
                            sdk.CredentialKind.TOTP,
                            sdk.CredentialKind.WEBUSERAPPROVAL,
                        ],
                    ),
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
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(ssh_target.id, role.id)

        totp = pyotp.TOTP(otp_key_base32)

        # Temp files for signaling between the expect script and this async task.
        # round2_ready: expect writes this after seeing the round-2 "Press Enter" prompt.
        # web_approved: Python writes this after approving browser auth.
        tmpdir = Path(tempfile.mkdtemp())
        round2_ready_flag = tmpdir / "round2_ready"
        web_approved_flag = tmpdir / "web_approved"

        script = dedent(
            f"""
            set timeout {timeout - 5}

            spawn ssh {user.username}:{ssh_target.name}@localhost \
                -p {shared_wg.ssh_port} \
                -o StrictHostKeychecking=no \
                -o UserKnownHostsFile=/dev/null \
                -o IdentitiesOnly=yes \
                -o IdentityFile=ssh-keys/id_ed25519 \
                -o PreferredAuthentications=publickey,keyboard-interactive \
                ls /bin/sh

            # Round 1 — both OTP and web approval prompts must appear.
            expect "One-time password:"
            sleep 0.5
            send "{totp.now()}\\r"

            expect "Press Enter when done:"
            send "\\r"

            # Round 2 — only the web approval prompt must appear, NOT the OTP prompt.
            # Matching "One-time password:" here is a test failure (exit 10).
            expect {{
                "One-time password:" {{ exit 10 }}
                "Press Enter when done:" {{ }}
            }}

            # Signal Python that the round-2 prompt has been seen.
            set fh [open "{round2_ready_flag}" w]
            close $fh

            # Wait for Python to approve browser auth before sending Enter.
            while {{![file exists "{web_approved_flag}"]}} {{
                sleep 0.1
            }}

            send "\\r"

            expect {{
                "/bin/sh" {{ exit 0 }}
                eof {{ exit 1 }}
            }}
            """
        )

        # Log in via HTTP to establish a session that can approve web auth requests.
        session = aiohttp.ClientSession()
        try:
            headers = {"Host": f"localhost:{shared_wg.http_port}"}
            await session.post(
                f"{url}/@warpgate/api/auth/login",
                json={"username": user.username, "password": "123"},
                headers=headers,
                ssl=False,
            )
            ws = await session.ws_connect(
                url.replace("https:", "wss:") + "/@warpgate/api/auth/web-auth-requests/stream",
                ssl=False,
            )

            expect_proc = processes.start(
                ["expect"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            # Write the script now so expect starts running immediately.
            # Null out stdin afterwards so communicate() doesn't try to flush
            # the already-closed pipe.
            expect_proc.stdin.write(script.encode())
            expect_proc.stdin.close()
            expect_proc.stdin = None

            # Receive the first web-auth notification (sent when round 1 starts).
            msg = await ws.receive(timeout)
            auth_id = msg.data

            # Poll until the expect script signals that the round-2 prompt is visible.
            while not round2_ready_flag.exists():
                await asyncio.sleep(0.1)

            # Verify the pending auth state before approving.
            auth_state_resp = await session.get(
                f"{url}/@warpgate/api/auth/state/{auth_id}", ssl=False
            )
            auth_state = await auth_state_resp.json()
            assert auth_state["protocol"] == "SSH"
            assert auth_state["state"] == "WebUserApprovalNeeded"

            # Approve browser auth.
            r = await session.post(
                f"{url}/@warpgate/api/auth/state/{auth_id}/approve", ssl=False
            )
            assert r.status == 200

            # Unblock the expect script so it can send Enter and complete.
            web_approved_flag.touch()

            output, stderr_out = expect_proc.communicate(timeout=timeout)
            assert expect_proc.returncode == 0, output + stderr_out
        finally:
            await session.close()
