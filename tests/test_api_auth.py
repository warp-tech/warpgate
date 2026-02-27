import contextlib
from uuid import uuid4
import requests
from .api_client import admin_client, sdk
from .conftest import WarpgateProcess
from .test_http_common import *  # noqa


@contextlib.contextmanager
def assert_401():
    with pytest.raises(sdk.ApiException) as e:
        yield
    assert e.value.status == 401


class TestAPIAuth:
    def test_unavailable_without_auth(
        self,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"

        config = sdk.Configuration(
            host=f"{url}/@warpgate/admin/api",
        )
        config.verify_ssl = False

        with sdk.ApiClient(config) as api_client:
            api = sdk.DefaultApi(api_client)
            with assert_401():
                api.get_parameters()
            with assert_401():
                api.get_role("1")
            with assert_401():
                api.get_roles()
            with assert_401():
                api.get_user("1")
            with assert_401():
                api.get_users()
            with assert_401():
                api.get_target("1")
            with assert_401():
                api.get_targets()
            with assert_401():
                api.get_session("1")
            with assert_401():
                api.get_sessions()

    def test_cookie_auth(
        self,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"

        with admin_client(url) as api:
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            admin_role = api.get_roles('warpgate:admin')[0]
            api.add_user_role(user.id, admin_role.id, sdk.AddUserRoleRequest(expires_at=None))

        session = requests.Session()
        session.verify = False
        r = session.post(
            f"{url}/@warpgate/api/auth/login",
            json={
                'username': user.username,
                'password': '123',
            },
        )
        assert r.status_code == 201, r.text

        r = session.get(f"{url}/@warpgate/admin/api/sessions")
        assert r.status_code == 200, r.text
