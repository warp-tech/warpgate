import requests
import pyotp
from base64 import b64decode
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import WarpgateProcess
from .test_http_common import *  # noqa


class TestHTTPUserAuthOTP:
    def test_auth_otp_success(
        self,
        otp_key_base32,
        otp_key_base64,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.create_otp_credential(
                user.id,
                sdk.NewOtpCredential(secret_key=list(b64decode(otp_key_base64))),
            )
            api.update_user(
                user.id,
                sdk.UserDataRequest(
                    username=user.username,
                    credential_policy=sdk.UserRequireCredentialsPolicy(
                        http=["Password", "Totp"]
                    ),
                ),
            )
            api.add_user_role(user.id, role.id)
            echo_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"echo-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetHTTPOptions(
                            kind="Http",
                            url=f"http://localhost:{echo_server_port}",
                            tls=sdk.Tls(
                                mode=sdk.TlsMode.DISABLED,
                                verify=False,
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(echo_target.id, role.id)

        session = requests.Session()
        session.verify = False

        totp = pyotp.TOTP(otp_key_base32)

        response = session.post(
            f"{url}/@warpgate/api/auth/login",
            json={
                "username": user.username,
                "password": "123",
            },
        )
        assert response.status_code // 100 != 2

        response = session.get(
            f"{url}/some/path?a=b&warpgate-target={echo_target.name}&c=d",
            allow_redirects=False,
        )
        assert response.status_code // 100 != 2

        response = session.post(
            f"{url}/@warpgate/api/auth/otp",
            json={
                "otp": totp.now(),
            },
        )
        assert response.status_code // 100 == 2

        response = session.get(
            f"{url}/some/path?a=b&warpgate-target={echo_target.name}&c=d",
            allow_redirects=False,
        )
        assert response.status_code // 100 == 2
        assert response.json()["path"] == "/some/path"

    def test_auth_otp_fail(
        self,
        otp_key_base64,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.create_otp_credential(
                user.id,
                sdk.NewOtpCredential(secret_key=list(b64decode(otp_key_base64))),
            )
            api.update_user(
                user.id,
                sdk.UserDataRequest(
                    username=user.username,
                    credential_policy=sdk.UserRequireCredentialsPolicy(
                        http=["Password", "Totp"]
                    ),
                ),
            )
            api.add_user_role(user.id, role.id)
            echo_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"echo-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetHTTPOptions(
                            kind="Http",
                            url=f"http://localhost:{echo_server_port}",
                            tls=sdk.Tls(
                                mode=sdk.TlsMode.DISABLED,
                                verify=False,
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(echo_target.id, role.id)

        session = requests.Session()
        session.verify = False

        response = session.post(
            f"{url}/@warpgate/api/auth/login",
            json={
                "username": user.username,
                "password": "123",
            },
        )
        assert response.status_code // 100 != 2

        response = session.post(
            f"{url}/@warpgate/api/auth/otp",
            json={
                "otp": "00000000",
            },
        )
        assert response.status_code // 100 != 2

        response = session.get(
            f"{url}/some/path?a=b&warpgate-target={echo_target.name}&c=d",
            allow_redirects=False,
        )
        assert response.status_code // 100 != 2
