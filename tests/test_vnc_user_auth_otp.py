from base64 import b64decode
from uuid import uuid4

import pyotp
import pytest

from .api_client import admin_client, sdk
from .conftest import VNC_BACKEND_SIZE, ProcessManager, WarpgateProcess
from .util import wait_port
from .vnc_client import VncClient, VncError


def _provision(api, vnc_port, otp_key_base64):
    role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
    user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
    api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
    api.create_otp_credential(
        user.id, sdk.NewOtpCredential(secret_key=list(b64decode(otp_key_base64)))
    )
    api.update_user(
        user.id,
        sdk.UserDataRequest(
            username=user.username,
            credential_policy=sdk.UserRequireCredentialsPolicy(
                vnc=[sdk.CredentialKind.PASSWORD, sdk.CredentialKind.TOTP],
            ),
        ),
    )
    api.add_user_role(user.id, role.id)
    target = api.create_target(
        sdk.TargetDataRequest(
            name=f"vnc-{uuid4()}",
            options=sdk.TargetOptions(
                sdk.TargetOptionsTargetVncOptions(
                    kind="Vnc",
                    host="localhost",
                    port=vnc_port,
                    auth=sdk.VncTargetAuth(
                        sdk.VncTargetAuthVncTargetPasswordAuth(
                            kind="Password", password="123"
                        )
                    ),
                )
            ),
        )
    )
    api.add_target_role(target.id, role.id)
    return user, target


class Test:
    def test_otp(
        self,
        processes: ProcessManager,
        otp_key_base32: str,
        otp_key_base64: str,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        vnc_port = processes.start_vnc_server()
        wait_port(vnc_port)
        wait_port(shared_wg.vnc_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, target = _provision(api, vnc_port, otp_key_base64)

        totp = pyotp.TOTP(otp_key_base32)
        client = VncClient(
            "localhost",
            shared_wg.vnc_port,
            f"{user.username}:{target.name}",
            "123",
            timeout=timeout,
        )
        try:
            client.connect()
            # The OTP field auto-submits once the 6th digit is typed.
            client.type_text(totp.now())
            assert client.wait_for_resize() == VNC_BACKEND_SIZE
        finally:
            client.close()

    def test_too_many_otp_disconnects(
        self,
        processes: ProcessManager,
        otp_key_base32: str,
        otp_key_base64: str,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        vnc_port = processes.start_vnc_server()
        wait_port(shared_wg.vnc_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, target = _provision(api, vnc_port, otp_key_base64)

        totp = pyotp.TOTP(otp_key_base32)
        wrong = "000000" if totp.now() != "000000" else "111111"

        client = VncClient(
            "localhost",
            shared_wg.vnc_port,
            f"{user.username}:{target.name}",
            "123",
            timeout=timeout,
        )
        try:
            client.connect()
            # Three incorrect codes must trip the attempt cap and drop the connection.
            for _ in range(3):
                client.type_text(wrong)
            with pytest.raises((VncError, OSError)):
                client.wait_for_resize()
        finally:
            client.close()
