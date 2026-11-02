"""
SCIM 2.0 provisioning (RFC 7643/7644) end to end: discovery and the bearer
gate, the user and group lifecycles with the request shapes Okta and Entra ID
send, deactivation ending sessions and refusing every login path, group
membership gating target access, a provisioned user logging in through OIDC,
and the audit trail naming the token.
"""

import subprocess
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .test_http_common import *  # noqa
from .test_http_user_auth_oidc import _do_oidc_login, _make_sso_provider_config
from .test_ssh_proto import common_args
from .util import alloc_port, wait_port

SCIM_PATH = "/@warpgate/scim/v2"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
ENTERPRISE_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


def _url(wg: WarpgateProcess) -> str:
    return f"https://localhost:{wg.http_port}"


def create_scim_token(wg: WarpgateProcess, sso_provider=None, expiry=None) -> str:
    with admin_client(_url(wg)) as api:
        created = api.create_scim_token(
            sdk.CreateScimTokenRequest(
                label=f"scim-{uuid4()}", sso_provider=sso_provider, expiry=expiry
            )
        )
    return created.secret


class Scim:
    """A SCIM client speaking to one Warpgate with one bearer token."""

    def __init__(
        self, wg: WarpgateProcess, secret: str, content_type="application/scim+json"
    ):
        self.base = f"{_url(wg)}{SCIM_PATH}"
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers["Authorization"] = f"Bearer {secret}"
        self.content_type = content_type

    def request(self, method, path, json=None, **kwargs):
        headers = kwargs.pop("headers", {})
        if json is not None:
            headers.setdefault("Content-Type", self.content_type)
        return self.session.request(
            method,
            f"{self.base}{path}",
            json=json,
            headers=headers,
            timeout=15,
            **kwargs,
        )

    def get(self, path, **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path, json, **kwargs):
        return self.request("POST", path, json=json, **kwargs)

    def put(self, path, json, **kwargs):
        return self.request("PUT", path, json=json, **kwargs)

    def patch(self, path, operations, **kwargs):
        return self.request(
            "PATCH",
            path,
            json={"schemas": [PATCH_SCHEMA], "Operations": operations},
            **kwargs,
        )

    def delete(self, path, **kwargs):
        return self.request("DELETE", path, **kwargs)

    # Helpers that assert the happy path
    def create_user(self, username, **attrs):
        body = {"schemas": [USER_SCHEMA], "userName": username, **attrs}
        r = self.post("/Users", body)
        assert r.status_code == 201, r.text
        return r.json()

    def create_group(self, name, members=(), **attrs):
        body = {
            "schemas": [GROUP_SCHEMA],
            "displayName": name,
            "members": [{"value": m} for m in members],
            **attrs,
        }
        r = self.post("/Groups", body)
        assert r.status_code == 201, r.text
        return r.json()


def _assert_scim_error(response, status, scim_type=None):
    assert response.status_code == status, response.text
    assert response.headers["Content-Type"].startswith("application/scim+json")
    body = response.json()
    assert body["schemas"] == [ERROR_SCHEMA]
    assert body["status"] == str(status)
    if scim_type:
        assert body["scimType"] == scim_type, body


def _ssh_target(api, ssh_port, role_id):
    target = api.create_target(
        sdk.TargetDataRequest(
            name=f"ssh-{uuid4()}",
            require_approval=False,
            ticket_requests_disabled=False,
            ticket_require_approval=False,
            options=sdk.TargetOptions(
                sdk.TargetOptionsTargetSSHOptions(
                    kind="Ssh",
                    allow_insecure_algos=False,
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
    api.add_target_role(target.id, role_id)
    return target


def _ssh(processes, wg, username, target_name, *command, password="123"):
    return processes.start_ssh_client(
        f"{username}:{target_name}@localhost",
        "-p",
        str(wg.ssh_port),
        *common_args,
        *command,
        password=password,
    )


def _ssh_works(processes, wg, username, target_name, timeout) -> bool:
    client = _ssh(processes, wg, username, target_name, "ls", "/bin/sh")
    out = client.communicate(timeout=timeout)[0]
    return client.returncode == 0 and out == b"/bin/sh\n"


def _ended_within(proc, seconds) -> bool:
    try:
        proc.wait(timeout=seconds)
        return True
    except subprocess.TimeoutExpired:
        return False


def _web_login(wg, username, password):
    session = requests.Session()
    session.verify = False
    response = session.post(
        f"{_url(wg)}/@warpgate/api/auth/login",
        json={"username": username, "password": password},
    )
    return session, response


class TestDiscoveryAndAuth:
    def test_bearer_gate(self, shared_wg: WarpgateProcess):
        url = f"{_url(shared_wg)}{SCIM_PATH}"
        anonymous = requests.Session()
        anonymous.verify = False

        r = anonymous.get(f"{url}/Users")
        _assert_scim_error(r, 401)
        assert r.headers["WWW-Authenticate"] == 'Bearer realm="warpgate"'

        r = anonymous.get(f"{url}/Users", headers={"Authorization": "Bearer nope"})
        _assert_scim_error(r, 401)

        # Neither the admin token nor an admin cookie opens the SCIM API.
        r = anonymous.get(f"{url}/Users", headers={"X-Warpgate-Token": "token-value"})
        _assert_scim_error(r, 401)
        session, login = _web_login(shared_wg, "admin", "123")
        assert login.status_code // 100 == 2
        r = session.get(f"{url}/Users")
        _assert_scim_error(r, 401)

        # A valid token works; a deleted one does not.
        label_prefix = f"gate-{uuid4()}"
        with admin_client(_url(shared_wg)) as api:
            created = api.create_scim_token(
                sdk.CreateScimTokenRequest(label=f"{label_prefix}-a")
            )
        scim = Scim(shared_wg, created.secret)
        assert scim.get("/Users").status_code == 200
        with admin_client(_url(shared_wg)) as api:
            mine = [t for t in api.get_scim_tokens() if t.label == f"{label_prefix}-a"]
            assert len(mine) == 1
            assert mine[0].last_used is not None
            api.delete_scim_token(mine[0].id)
        _assert_scim_error(scim.get("/Users"), 401)

        # An expired one does not either.
        soon = datetime.now(timezone.utc) + timedelta(seconds=3)
        short_lived = Scim(shared_wg, create_scim_token(shared_wg, expiry=soon))
        assert short_lived.get("/Users").status_code == 200
        time.sleep(4)
        _assert_scim_error(short_lived.get("/Users"), 401)

    def test_discovery_documents(self, shared_wg: WarpgateProcess):
        scim = Scim(shared_wg, create_scim_token(shared_wg))

        r = scim.get("/ServiceProviderConfig")
        assert r.status_code == 200
        assert r.headers["Content-Type"].startswith("application/scim+json")
        config = r.json()
        assert config["patch"]["supported"] is True
        assert config["bulk"]["supported"] is False
        assert config["filter"]["supported"] is True
        assert config["authenticationSchemes"][0]["type"] == "oauthbearertoken"
        assert config["meta"]["location"].endswith(
            f"{SCIM_PATH}/ServiceProviderConfig"
        )

        types = scim.get("/ResourceTypes").json()
        assert types["schemas"] == [LIST_SCHEMA]
        assert {t["id"] for t in types["Resources"]} == {"User", "Group"}
        assert scim.get("/ResourceTypes/User").json()["endpoint"] == "/Users"
        _assert_scim_error(scim.get("/ResourceTypes/Robot"), 404)

        schemas = scim.get("/Schemas").json()
        assert {s["id"] for s in schemas["Resources"]} == {
            USER_SCHEMA,
            GROUP_SCHEMA,
            ENTERPRISE_SCHEMA,
        }
        assert scim.get(f"/Schemas/{GROUP_SCHEMA}").json()["name"] == "Group"

        _assert_scim_error(scim.post("/Bulk", {}), 501)
        _assert_scim_error(scim.get("/Me"), 501)
        _assert_scim_error(scim.get("/Nothing"), 404)
        _assert_scim_error(scim.delete("/Users"), 405)


class TestUsers:
    def test_lifecycle(self, shared_wg: WarpgateProcess):
        scim = Scim(shared_wg, create_scim_token(shared_wg))
        username = f"alice-{uuid4()}"
        external_id = f"ext-{uuid4()}"

        r = scim.post(
            "/Users",
            {
                "schemas": [USER_SCHEMA, ENTERPRISE_SCHEMA],
                "userName": username,
                "externalId": external_id,
                "active": True,
                "name": {"givenName": "Alice", "familyName": "Smith"},
                "displayName": "Alice Smith",
                "emails": [
                    {"value": "alice@example.com", "primary": True, "type": "work"}
                ],
                ENTERPRISE_SCHEMA: {"department": "ops"},
            },
        )
        assert r.status_code == 201, r.text
        assert r.headers["Content-Type"].startswith("application/scim+json")
        user = r.json()
        user_id = user["id"]
        assert r.headers["Location"].endswith(f"{SCIM_PATH}/Users/{user_id}")
        assert user["meta"]["location"] == r.headers["Location"]
        assert user["userName"] == username
        assert user["externalId"] == external_id
        assert user["active"] is True
        assert user["name"]["familyName"] == "Smith"
        assert user[ENTERPRISE_SCHEMA]["department"] == "ops"
        assert user["groups"] == []
        assert user["meta"]["resourceType"] == "User"
        assert user["meta"]["created"].endswith("Z")
        assert user["meta"]["lastModified"] >= user["meta"]["created"]

        # The admin API sees the same account.
        with admin_client(_url(shared_wg)) as api:
            admin_user = api.get_user(user_id)
            assert admin_user.username == username
            assert admin_user.scim_external_id == external_id
            assert admin_user.enabled is True
            assert admin_user.created_at is not None

        # Uniqueness is case-insensitive.
        _assert_scim_error(
            scim.post(
                "/Users", {"schemas": [USER_SCHEMA], "userName": username.upper()}
            ),
            409,
            "uniqueness",
        )
        _assert_scim_error(
            scim.post("/Users", {"schemas": [USER_SCHEMA]}), 400, "invalidValue"
        )
        _assert_scim_error(
            scim.post("/Users", {"schemas": [USER_SCHEMA], "userName": "a:b"}),
            400,
            "invalidValue",
        )
        _assert_scim_error(
            scim.post("/Users", "not json", headers={"Content-Type": "text/plain"}),
            400,
        )

        assert scim.get(f"/Users/{user_id}").json() == user
        _assert_scim_error(scim.get(f"/Users/{uuid4()}"), 404)
        _assert_scim_error(scim.get("/Users/not-a-uuid"), 404)

        # Filtering, the way identity providers look users up.
        for filter_ in [
            f'userName eq "{username.upper()}"',
            f'externalId eq "{external_id}"',
            'emails[type eq "work"].value co "alice@" and active eq true',
            f'{USER_SCHEMA}:userName eq "{username}"',
        ]:
            listed = scim.get("/Users", params={"filter": filter_}).json()
            assert listed["schemas"] == [LIST_SCHEMA]
            assert listed["totalResults"] == 1, filter_
            assert listed["Resources"][0]["id"] == user_id
        assert (
            scim.get("/Users", params={"filter": 'userName eq "nobody"'}).json()[
                "totalResults"
            ]
            == 0
        )
        _assert_scim_error(
            scim.get("/Users", params={"filter": "userName"}), 400, "invalidFilter"
        )
        _assert_scim_error(
            scim.get("/Users", params={"count": "x"}), 400, "invalidValue"
        )

        searched = scim.post(
            "/Users/.search",
            {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
                "filter": f'userName eq "{username}"',
                "count": 1,
            },
        ).json()
        assert searched["totalResults"] == 1
        assert searched["itemsPerPage"] == 1

        # Pagination over everything.
        everything = scim.get("/Users", params={"sortBy": "userName"}).json()
        total = everything["totalResults"]
        assert total >= 2
        page = scim.get(
            "/Users", params={"sortBy": "userName", "startIndex": 2, "count": 1}
        ).json()
        assert page["startIndex"] == 2
        assert page["itemsPerPage"] == 1
        assert page["totalResults"] == total
        assert page["Resources"][0]["id"] == everything["Resources"][1]["id"]

        # PUT replaces the resource; attributes left out are cleared.
        replaced = scim.put(
            f"/Users/{user_id}",
            {"schemas": [USER_SCHEMA], "userName": username, "title": "Engineer"},
        )
        assert replaced.status_code == 200, replaced.text
        replaced = replaced.json()
        assert replaced["title"] == "Engineer"
        assert "name" not in replaced
        assert "externalId" not in replaced
        assert replaced["active"] is True

        # Entra ID: capitalised op, string boolean.
        patched = scim.patch(
            f"/Users/{user_id}",
            [{"op": "Replace", "path": "active", "value": "False"}],
        )
        assert patched.status_code == 200, patched.text
        assert patched.json()["active"] is False
        assert scim.get(f"/Users/{user_id}").json()["active"] is False

        # Okta: path-less replace with an object, with `id` echoed back.
        patched = scim.patch(
            f"/Users/{user_id}",
            [
                {
                    "op": "replace",
                    "value": {"id": user_id, "active": True, "externalId": "new-ext"},
                }
            ],
        )
        assert patched.status_code == 200, patched.text
        assert patched.json()["active"] is True
        assert patched.json()["externalId"] == "new-ext"

        _assert_scim_error(
            scim.patch(
                f"/Users/{user_id}",
                [{"op": "add", "path": "groups", "value": [{"value": "x"}]}],
            ),
            400,
            "mutability",
        )
        _assert_scim_error(
            scim.patch(
                f"/Users/{user_id}", [{"op": "replace", "path": "a b", "value": 1}]
            ),
            400,
            "invalidPath",
        )
        _assert_scim_error(
            scim.patch(
                f"/Users/{uuid4()}",
                [{"op": "replace", "path": "active", "value": True}],
            ),
            404,
        )

        assert scim.delete(f"/Users/{user_id}").status_code == 204
        _assert_scim_error(scim.get(f"/Users/{user_id}"), 404)
        _assert_scim_error(scim.delete(f"/Users/{user_id}"), 404)
        with admin_client(_url(shared_wg)) as api:
            assert all(u.id != user_id for u in api.get_users())

    def test_plain_json_content_type_is_accepted(self, shared_wg: WarpgateProcess):
        scim = Scim(
            shared_wg, create_scim_token(shared_wg), content_type="application/json"
        )
        user = scim.create_user(f"json-{uuid4()}")
        assert scim.delete(f"/Users/{user['id']}").status_code == 204


class TestDeactivation:
    def test_deactivation_ends_sessions_and_blocks_every_login(
        self,
        processes: ProcessManager,
        shared_wg: WarpgateProcess,
        wg_c_ed25519_pubkey,
        timeout,
    ):
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)
        scim = Scim(shared_wg, create_scim_token(shared_wg))

        user = scim.create_user(f"dan-{uuid4()}")
        group = scim.create_group(f"ops-{uuid4()}", members=[user["id"]])
        with admin_client(_url(shared_wg)) as api:
            api.create_password_credential(
                user["id"], sdk.NewPasswordCredential(password="123")
            )
            target = _ssh_target(api, ssh_port, group["id"])
        username = user["userName"]

        assert _ssh_works(processes, shared_wg, username, target.name, timeout)
        long_session = _ssh(
            processes, shared_wg, username, target.name, "sh", "-c", "'sleep 120'"
        )
        assert not _ended_within(long_session, 8), "the session did not start"

        # A web session and an API token minted before deactivation.
        web, login = _web_login(shared_wg, username, "123")
        assert login.status_code // 100 == 2, login.text
        token = web.post(
            f"{_url(shared_wg)}/@warpgate/api/profile/api-tokens",
            json={
                "label": "t",
                "expiry": (
                    datetime.now(timezone.utc) + timedelta(hours=1)
                ).isoformat(),
            },
        )
        assert token.status_code == 201, token.text
        api_token = token.json()["secret"]
        info = requests.get(
            f"{_url(shared_wg)}/@warpgate/api/info",
            headers={"X-Warpgate-Token": api_token},
            verify=False,
        )
        assert info.json()["username"] == username

        r = scim.patch(
            f"/Users/{user['id']}",
            [{"op": "Replace", "path": "active", "value": "False"}],
        )
        assert r.status_code == 200, r.text

        assert _ended_within(long_session, 15), "the session outlived the deactivation"
        assert not _ssh_works(processes, shared_wg, username, target.name, timeout)
        _, login = _web_login(shared_wg, username, "123")
        assert login.status_code // 100 != 2
        info = requests.get(
            f"{_url(shared_wg)}/@warpgate/api/info",
            headers={"X-Warpgate-Token": api_token},
            verify=False,
        )
        assert info.json().get("username") is None, info.text
        assert (
            web.get(f"{_url(shared_wg)}/@warpgate/api/info").json().get("username")
            is None
        )
        with admin_client(_url(shared_wg)) as api:
            assert api.get_user(user["id"]).enabled is False

        r = scim.patch(
            f"/Users/{user['id']}", [{"op": "replace", "value": {"active": True}}]
        )
        assert r.status_code == 200, r.text
        assert _ssh_works(processes, shared_wg, username, target.name, timeout)

    def test_the_admin_api_can_disable_too(self, shared_wg: WarpgateProcess):
        with admin_client(_url(shared_wg)) as api:
            user = api.create_user(sdk.CreateUserRequest(username=f"eve-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            assert _web_login(shared_wg, user.username, "123")[1].status_code // 100 == 2
            updated = api.update_user(
                user.id, sdk.UserDataRequest(username=user.username, enabled=False)
            )
            assert updated.enabled is False
            assert _web_login(shared_wg, user.username, "123")[1].status_code // 100 != 2
            # Left out, the flag is unchanged.
            assert (
                api.update_user(
                    user.id, sdk.UserDataRequest(username=user.username)
                ).enabled
                is False
            )
            assert (
                api.update_user(
                    user.id, sdk.UserDataRequest(username=user.username, enabled=True)
                ).enabled
                is True
            )
            assert _web_login(shared_wg, user.username, "123")[1].status_code // 100 == 2


class TestGroups:
    def test_membership_gates_access(
        self,
        processes: ProcessManager,
        shared_wg: WarpgateProcess,
        wg_c_ed25519_pubkey,
        timeout,
    ):
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)
        scim = Scim(shared_wg, create_scim_token(shared_wg))
        user = scim.create_user(f"gina-{uuid4()}")
        username = user["userName"]

        # An admin-created role with a target grant is linked by name.
        with admin_client(_url(shared_wg)) as api:
            api.create_password_credential(
                user["id"], sdk.NewPasswordCredential(password="123")
            )
            role = api.create_role(sdk.RoleDataRequest(name=f"Prod-{uuid4()}"))
            target = _ssh_target(api, ssh_port, role.id)
        listed = scim.get(
            "/Groups", params={"filter": f'displayName eq "{role.name.lower()}"'}
        ).json()
        assert listed["totalResults"] == 1
        assert listed["Resources"][0]["id"] == role.id
        assert listed["Resources"][0]["members"] == []

        assert not _ssh_works(processes, shared_wg, username, target.name, timeout)

        # Entra ID adds the member ...
        r = scim.patch(
            f"/Groups/{role.id}",
            [{"op": "Add", "path": "members", "value": [{"value": user["id"]}]}],
        )
        assert r.status_code == 200, r.text
        assert [m["value"] for m in r.json()["members"]] == [user["id"]]
        assert r.json()["members"][0]["display"] == username
        assert scim.get(f"/Users/{user['id']}").json()["groups"][0]["value"] == role.id
        assert _ssh_works(processes, shared_wg, username, target.name, timeout)
        with admin_client(_url(shared_wg)) as api:
            assert [a.id for a in api.get_user_roles(user["id"]) if a.is_active] == [
                role.id
            ]

        # ... and removes it again by filter while a session is open.
        long_session = _ssh(
            processes, shared_wg, username, target.name, "sh", "-c", "'sleep 120'"
        )
        assert not _ended_within(long_session, 8), "the session did not start"
        r = scim.patch(
            f"/Groups/{role.id}",
            [{"op": "Remove", "path": f'members[value eq "{user["id"]}"]'}],
        )
        assert r.status_code == 200, r.text
        assert r.json()["members"] == []
        assert _ended_within(long_session, 15), "the session outlived the membership"
        assert not _ssh_works(processes, shared_wg, username, target.name, timeout)
        with admin_client(_url(shared_wg)) as api:
            assignments = api.get_user_roles(user["id"])
            assert len(assignments) == 1 and not assignments[0].is_active

        # Okta: replace the whole member list, then PUT.
        r = scim.patch(
            f"/Groups/{role.id}",
            [{"op": "replace", "value": {"members": [{"value": user["id"]}]}}],
        )
        assert r.status_code == 200, r.text
        assert _ssh_works(processes, shared_wg, username, target.name, timeout)
        r = scim.put(
            f"/Groups/{role.id}",
            {
                "schemas": [GROUP_SCHEMA],
                "id": role.id,
                "displayName": role.name,
                "members": [],
            },
        )
        assert r.status_code == 200, r.text
        assert r.json()["members"] == []
        assert not _ssh_works(processes, shared_wg, username, target.name, timeout)

    def test_group_lifecycle(self, shared_wg: WarpgateProcess):
        scim = Scim(shared_wg, create_scim_token(shared_wg))
        alice = scim.create_user(f"alice-{uuid4()}")
        bob = scim.create_user(f"bob-{uuid4()}")
        name = f"Ops-{uuid4()}"

        r = scim.post(
            "/Groups",
            {
                "schemas": [GROUP_SCHEMA],
                "displayName": name,
                "externalId": "g-ext",
                "members": [
                    {"value": alice["id"], "display": "ignored"},
                    {"value": bob["id"]},
                ],
            },
        )
        assert r.status_code == 201, r.text
        group = r.json()
        assert r.headers["Location"].endswith(f"/Groups/{group['id']}")
        assert group["displayName"] == name
        assert group["externalId"] == "g-ext"
        assert {m["value"] for m in group["members"]} == {alice["id"], bob["id"]}
        assert group["meta"]["resourceType"] == "Group"
        last_modified = group["meta"]["lastModified"]

        _assert_scim_error(
            scim.post(
                "/Groups", {"schemas": [GROUP_SCHEMA], "displayName": name.lower()}
            ),
            409,
            "uniqueness",
        )
        _assert_scim_error(
            scim.post(
                "/Groups",
                {
                    "schemas": [GROUP_SCHEMA],
                    "displayName": "x",
                    "members": [{"value": str(uuid4())}],
                },
            ),
            400,
            "invalidValue",
        )
        _assert_scim_error(
            scim.post("/Groups", {"schemas": [GROUP_SCHEMA]}), 400, "invalidValue"
        )

        with admin_client(_url(shared_wg)) as api:
            role = api.get_role(group["id"])
            assert role.name == name
            assert {u.id for u in api.get_role_users(group["id"])} == {
                alice["id"],
                bob["id"],
            }

        assert (
            scim.get("/Groups", params={"filter": 'externalId eq "G-EXT"'}).json()[
                "totalResults"
            ]
            == 1
        )

        time.sleep(1.1)
        r = scim.patch(
            f"/Groups/{group['id']}",
            [{"op": "remove", "path": "members", "value": [{"value": bob["id"]}]}],
        )
        assert r.status_code == 200, r.text
        assert [m["value"] for m in r.json()["members"]] == [alice["id"]]
        assert r.json()["meta"]["lastModified"] > last_modified, (
            "a membership change moves lastModified"
        )

        r = scim.patch(
            f"/Groups/{group['id']}",
            [{"op": "replace", "path": "displayName", "value": f"{name}-renamed"}],
        )
        assert r.status_code == 200, r.text
        assert r.json()["displayName"] == f"{name}-renamed"
        _assert_scim_error(
            scim.patch(
                f"/Groups/{group['id']}",
                [{"op": "replace", "path": "id", "value": "x"}],
            ),
            400,
            "mutability",
        )

        assert scim.delete(f"/Groups/{group['id']}").status_code == 204
        _assert_scim_error(scim.get(f"/Groups/{group['id']}"), 404)
        with admin_client(_url(shared_wg)) as api:
            assert all(r.id != group["id"] for r in api.get_roles())
            assert api.get_user_roles(alice["id"]) == []
        assert scim.get(f"/Users/{alice['id']}").json()["groups"] == []


class TestSsoLink:
    def test_provisioned_user_logs_in_through_oidc(
        self, processes: ProcessManager, echo_server_port
    ):
        wg_http_port = alloc_port()
        oidc_port = processes.start_oidc_server(wg_http_port)
        wg = processes.start_wg(
            http_port=wg_http_port,
            config_patch={
                "sso_providers": [_make_sso_provider_config(oidc_port)],
                "external_host": "127.0.0.1",
            },
        )
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        wg_url = f"https://127.0.0.1:{wg.http_port}"

        with admin_client(wg_url) as api:
            # The provider must exist.
            try:
                api.create_scim_token(
                    sdk.CreateScimTokenRequest(label="x", sso_provider="nope")
                )
                raise AssertionError("an unknown SSO provider was accepted")
            except sdk.ApiException as e:
                assert e.status == 400
            api.update_parameters(sdk.ParameterUpdate(login_protection_enabled=False))

        scim = Scim(wg, create_scim_token(wg, sso_provider="test-oidc"))
        user = scim.create_user(
            "sam_tailor",
            emails=[
                {"value": "other@example.com", "type": "home"},
                {"value": "sam.tailor@gmail.com", "type": "work", "primary": True},
            ],
        )
        group = scim.create_group("oidc-ops", members=[user["id"]])
        with admin_client(wg_url) as api:
            target = api.create_target(
                sdk.TargetDataRequest(
                    name="echo",
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetHTTPOptions(
                            kind="Http",
                            headers={},
                            url=f"http://localhost:{echo_server_port}",
                            tls=sdk.Tls(mode=sdk.TlsMode.DISABLED, verify=False),
                        )
                    ),
                )
            )
            api.add_target_role(target.id, group["id"])
            creds = api.get_sso_credentials(user["id"])
            assert [(c.provider, c.email) for c in creds] == [
                ("test-oidc", "sam.tailor@gmail.com")
            ]

        session, resp = _do_oidc_login(wg_url, oidc_port)
        assert resp.status_code in (302, 307), resp.text[:300]
        assert "login_error" not in resp.headers["Location"]
        info = session.get(f"{wg_url}/@warpgate/api/info").json()
        assert info["username"] == "sam_tailor"
        targets = session.get(f"{wg_url}/@warpgate/api/targets").json()
        assert [t["name"] for t in targets] == ["echo"]

        # A changed primary email moves the credential, so the old identity
        # no longer logs in.
        r = scim.patch(
            f"/Users/{user['id']}",
            [
                {
                    "op": "replace",
                    "path": 'emails[type eq "work"].value',
                    "value": "sam.new@example.com",
                }
            ],
        )
        assert r.status_code == 200, r.text
        with admin_client(wg_url) as api:
            creds = api.get_sso_credentials(user["id"])
            assert [c.email for c in creds] == ["sam.new@example.com"]
        _, resp = _do_oidc_login(wg_url, oidc_port)
        assert "login_error" in resp.headers["Location"]


class TestAudit:
    def test_audit_lines_name_the_token(self, processes: ProcessManager, timeout):
        wg = processes.start_wg()
        wait_port(wg.http_port, for_process=wg.process, recv=False, timeout=timeout)
        with admin_client(_url(wg)) as api:
            created = api.create_scim_token(
                sdk.CreateScimTokenRequest(label="okta-prod")
            )
        scim = Scim(wg, created.secret)
        user = scim.create_user("audited")
        group = scim.create_group("audited-group", members=[user["id"]])
        scim.patch(
            f"/Users/{user['id']}",
            [{"op": "replace", "path": "active", "value": False}],
        )
        scim.delete(f"/Groups/{group['id']}")
        scim.delete(f"/Users/{user['id']}")
        time.sleep(1)

        log = wg.log_path.read_text()
        for needle in [
            "Created SCIM token",
            "Created user",
            "Granted access role",
            "Disabled user",
            "Revoked access role",
            "Deleted user",
        ]:
            assert needle in log, f"no audit line for {needle!r}"
        # Every SCIM request runs in a span naming the token, which the console
        # format prints ahead of the message.
        scim_lines = [line for line in log.splitlines() if "okta-prod" in line]
        assert any("Created user" in line for line in scim_lines), scim_lines[:5]
        assert any("Deleted user" in line for line in scim_lines), scim_lines[:5]
