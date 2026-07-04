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
    def test_otp_required_rejects_native_rdp(
        self,
        processes: ProcessManager,
        otp_key_base64: str,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # Native RDP collects only username+password over NLA, so a policy that also
        # requires TOTP can't be satisfied — the correct password alone is rejected
        # (the second factor can't be gathered over the RDP auth exchange).
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
            # The password alone can't satisfy the TOTP factor, so Warpgate must not
            # authorize — no session is ever stamped with this user.
            assert not rdp_session_authorized(api, user.username), (
                "OTP-required user was authorized over native RDP with the password alone"
            )
