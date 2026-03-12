import contextlib
from uuid import uuid4
import pytest
import requests

from .api_client import sdk
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
        admin_client,
    ):
        url = f"https://localhost:{shared_wg.http_port}"

        # ``admin_client`` fixture already points at ``/@warpgate/admin/api``
        api = admin_client
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        api.create_password_credential(
            user.id, sdk.NewPasswordCredential(password="123")
        )
        admin_role = api.get_roles("warpgate:admin")[0]
        api.add_user_role(user.id, admin_role.id)

        session = requests.Session()
        session.verify = False
        r = session.post(
            f"{url}/@warpgate/api/auth/login",
            json={
                "username": user.username,
                "password": "123",
            },
        )
        assert r.status_code == 201, r.text

        r = session.get(f"{url}/@warpgate/admin/api/sessions")
        assert r.status_code == 200, r.text

    def test_permission_enforcement(self, shared_wg: WarpgateProcess, admin_client):
        # create a new user and give them a custom limited admin role
        url = f"https://localhost:{shared_wg.http_port}"
        admin_token = "token-value"

        # create limited admin role via direct HTTP (skip SDK)
        role_payload = {
            "name": "limited",
            "description": "limited permissions",
            "targets_create": False,
            "targets_edit": False,
            "targets_delete": False,
            "users_create": True,
            "users_edit": True,
            "users_delete": False,
            "access_roles_create": False,
            "access_roles_edit": False,
            "access_roles_delete": False,
            "access_roles_assign": False,
            "sessions_view": False,
            "sessions_terminate": False,
            "recordings_view": False,
            "config_edit": False,
            "admin_roles_manage": False,
        }
        headers = {"X-Warpgate-Token": admin_token}
        r = requests.post(
            f"{url}/@warpgate/admin/api/admin-roles",
            json=role_payload,
            headers=headers,
            verify=False,
        )
        assert r.status_code == 201, r.text
        limited = r.json()

        assert limited["users_create"] is True
        assert limited["users_edit"] is True

        # fetching the role separately yields the same enforced values
        r2 = requests.get(
            f"{url}/@warpgate/admin/api/admin-roles/{limited['id']}",
            headers=headers,
            verify=False,
        )
        assert r2.status_code == 200
        fetched = r2.json()
        assert fetched["users_edit"] is True

        # use fixture instead of manual context manager
        api = admin_client
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        api.create_password_credential(
            user.id, sdk.NewPasswordCredential(password="123")
        )
        # assign limited admin role
        r = requests.post(
            f"{url}/@warpgate/admin/api/users/{user.id}/admin-roles/{limited['id']}",
            headers=headers,
            verify=False,
        )
        assert r.status_code == 201

        # login as limited user
        session = requests.Session()
        session.verify = False
        r = session.post(
            f"{url}/@warpgate/api/auth/login",
            json={"username": user.username, "password": "123"},
        )
        assert r.status_code == 201

        # try to create user (should succeed because users_create= True)
        r = session.post(f"{url}/@warpgate/admin/api/users", json={"username": "foo"})
        assert r.status_code == 201
        created = r.json()

        # Because normalization should have added users_edit, the limited user
        # should now also be able to edit the user they just created.
        r = session.put(
            f"{url}/@warpgate/admin/api/users/{created['id']}",
            json={"username": "foo-renamed"},
        )
        assert r.status_code == 200

        # try to create target (should 403)
        r = session.post(
            f"{url}/@warpgate/admin/api/targets",
            json={
                "name": "x",
                "options": {
                    "kind": "Ssh",
                    "host": "a",
                    "port": 22,
                    "username": "u",
                    "auth": {"kind": "PublicKey"},
                },
            },
        )
        assert r.status_code == 403

        # try to view sessions (should 403)
        r = session.get(f"{url}/@warpgate/admin/api/sessions")
        assert r.status_code == 403

        # upgrade the role to have sessions_view and test again
        role_payload["sessions_view"] = True
        r = requests.put(
            f"{url}/@warpgate/admin/api/admin-roles/{limited['id']}",
            json=role_payload,
            headers=headers,
            verify=False,
        )
        assert r.status_code == 200

        r = session.get(f"{url}/@warpgate/admin/api/sessions")
        assert r.status_code == 200
