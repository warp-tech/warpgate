from datetime import datetime, timedelta, timezone
from uuid import uuid4

import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .test_api import _create_user_api_token, _create_user_with_role
from .test_ticket_requests import _default_params
from .util import wait_port


def _token_client(url: str) -> tuple[requests.Session, requests.Session]:
    """A fresh user as two clients: one using an API token, one a web session."""
    with admin_client(url) as api:
        user = _create_user_with_role(api, None)
    token = _create_user_api_token(url, user.username, "123")

    by_token = requests.Session()
    by_token.verify = False
    by_token.headers["X-Warpgate-Token"] = token

    by_session = requests.Session()
    by_session.verify = False
    by_session.post(
        f"{url}/@warpgate/api/auth/login",
        json={"username": user.username, "password": "123"},
    ).raise_for_status()
    return by_token, by_session


def test_token_cannot_mint_tokens_or_change_credentials(shared_wg: WarpgateProcess):
    url = f"https://localhost:{shared_wg.http_port}"
    api = f"{url}/@warpgate/api"
    by_token, by_session = _token_client(url)

    assert by_token.get(f"{api}/profile/api-tokens").status_code == 200

    expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    new_token = {"label": "second", "expiry": expiry}
    new_password = {"password": "456"}
    assert by_token.post(f"{api}/profile/api-tokens", json=new_token).status_code == 401
    assert (
        by_token.post(f"{api}/profile/credentials/password", json=new_password).status_code
        == 401
    )
    # A junk session cookie next to the token does not turn it into a session.
    assert (
        by_token.post(
            f"{api}/profile/api-tokens",
            json=new_token,
            cookies={"warpgate-http-session": "junk"},
        ).status_code
        == 401
    )

    assert by_session.post(f"{api}/profile/api-tokens", json=new_token).status_code == 201
    assert (
        by_session.post(
            f"{api}/profile/credentials/password", json=new_password
        ).status_code
        != 401
    )


def test_token_endpoint_allowlist(processes: ProcessManager):
    wg = processes.start_wg(
        config_patch={
            "http": {
                "user_api_token_allowed_endpoints": [
                    "GET /@warpgate/api/info",
                    "get /@warpgate/api/profile/api-tokens",
                    "GET /@warpgate/admin/api/users",
                ]
            }
        }
    )
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    url = f"https://localhost:{wg.http_port}"
    by_token, by_session = _token_client(url)

    for method, path, allowed in [
        ("GET", "/@warpgate/api/info", True),
        ("GET", "/@warpgate/api/profile/api-tokens", True),
        ("DELETE", f"/@warpgate/api/profile/api-tokens/{uuid4()}", False),
        ("GET", "/@warpgate/api/profile/api-tokens/", False),
        ("GET", "/@warpgate/api/targets", False),
        ("POST", "/@warpgate/api/info", False),
        ("GET", "/_warpgate/api/info", False),
        ("GET", "/@warpgate/admin/api/roles", False),
    ]:
        status = by_token.request(method, f"{url}{path}").status_code
        assert (status != 403) == allowed, (method, path, status)

    # Past the allowlist the admin API still applies its own permission check.
    assert by_token.get(f"{url}/@warpgate/admin/api/users").status_code == 401

    # Sessions and the admin token are not subject to the list.
    assert by_session.get(f"{url}/@warpgate/api/targets").status_code == 200
    with admin_client(url) as api:
        api.get_roles()


def test_token_never_satisfies_login_age_policy(shared_wg: WarpgateProcess):
    url = f"https://localhost:{shared_wg.http_port}"
    by_token, by_session = _token_client(url)

    # The policy is checked before the target is looked up, so an unknown target
    # tells "refused by policy" (401) apart from "allowed to try" (404).
    def start_web_ssh(client: requests.Session) -> int:
        return client.post(
            f"{url}/@warpgate/api/web-ssh/sessions", json={"target_id": str(uuid4())}
        ).status_code

    assert start_web_ssh(by_token) == 404
    with admin_client(url) as api:
        api.update_parameters(_default_params(web_auth_max_age_seconds=3600))
    try:
        assert start_web_ssh(by_token) == 401
        assert start_web_ssh(by_session) == 404
    finally:
        with admin_client(url) as api:
            api.update_parameters(_default_params(web_auth_max_age_seconds=None))
