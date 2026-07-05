from base64 import b64decode
from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess, rdp_session_authorized
from .rdp_client import full_connect, have_xfreerdp
from .util import wait_port

pytestmark = pytest.mark.skipif(
    not have_xfreerdp(), reason="FreeRDP (xfreerdp) is not installed"
)


def _provision(api, otp_key_base64):
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
                rdp=[sdk.CredentialKind.PASSWORD, sdk.CredentialKind.TOTP],
            ),
        ),
    )
    api.add_user_role(user.id, role.id)
    target = api.create_target(
        sdk.TargetDataRequest(
            name=f"rdp-{uuid4()}",
            options=sdk.TargetOptions(
                sdk.TargetOptionsTargetRdpOptions(
                    kind="Rdp",
                    # Never dialed: auth is rejected before Warpgate connects the target.
                    host="localhost",
                    port=3389,
                    username="user",
                    auth=sdk.RdpTargetAuth(
                        sdk.RdpTargetAuthRdpTargetPasswordAuth(
                            kind="Password", password="123"
                        )
                    ),
                    verify_tls=False,
                )
            ),
        )
    )
    api.add_target_role(target.id, role.id)
    return user, target


class Test:
    def test_otp_required_not_authorized_without_second_factor(
        self,
        processes: ProcessManager,
        otp_key_base64: str,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # A TOTP-required user is prompted for the code on the RDP hold screen after NLA.
        # This client connects but never enters it, so Warpgate must never authorize —
        # it stamps the session username only once the second factor completes (in
        # `connect_backend`), so no session is ever stamped with this user.
        wait_port(shared_wg.rdp_port, recv=False)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, target = _provision(api, otp_key_base64)
            full_connect(
                "localhost",
                shared_wg.rdp_port,
                f"{user.username}:{target.name}",
                "123",
                timeout,
            )
            assert not rdp_session_authorized(api, user.username), (
                "OTP-required user was authorized over native RDP without the second factor"
            )
