from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import requests

from .api_client import sdk, admin_client as new_admin_client
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port

ALLOWED_IP = "9.9.9.9"
DENIED_IP = "8.8.8.8"


@pytest.fixture(scope="session")
def proxied_wg(processes: ProcessManager):
    # The allow-list is only meaningfully testable from a single test host if
    # the client IP is header-supplied, which is also the reverse-proxy
    # deployment the check has to be correct for.
    wg = processes.start_wg(config_patch={"http": {"trust_x_forwarded_headers": True}})
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    yield wg


@pytest.fixture
def ip_restricted_user(proxied_wg: WarpgateProcess):
    url = f"https://localhost:{proxied_wg.http_port}"
    with new_admin_client(url) as admin:
        user = admin.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        admin.create_password_credential(
            user.id, sdk.NewPasswordCredential(password="123")
        )
        yield url, user, admin


def _login(url: str, username: str, ip: str) -> tuple[requests.Session, requests.Response]:
    session = requests.Session()
    session.verify = False
    session.headers["X-Forwarded-For"] = ip
    return session, session.post(
        f"{url}/@warpgate/api/auth/login",
        json={"username": username, "password": "123"},
    )


def _restrict(admin: sdk.DefaultApi, user, ranges: list[str]):
    admin.update_user(
        user.id,
        sdk.UserDataRequest(username=user.username, allowed_ip_ranges=ranges),
    )


def test_login_honours_forwarded_client_ip(ip_restricted_user):
    url, user, admin = ip_restricted_user
    _restrict(admin, user, [f"{ALLOWED_IP}/32"])

    _, allowed = _login(url, user.username, ALLOWED_IP)
    assert allowed.status_code == 201

    _, denied = _login(url, user.username, DENIED_IP)
    assert denied.status_code == 401
    assert denied.json()["state"] == "IpRejected"


def test_api_token_is_bound_to_the_users_allowed_ranges(ip_restricted_user):
    url, user, admin = ip_restricted_user

    # Mint the token before the restriction exists, so the token itself is
    # unquestionably valid and only the presenting IP differs between the
    # two assertions below.
    session, _ = _login(url, user.username, DENIED_IP)
    minted = session.post(
        f"{url}/@warpgate/api/profile/api-tokens",
        json={
            "label": "test",
            "expiry": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        },
    )
    minted.raise_for_status()
    token = minted.json()["secret"]

    _restrict(admin, user, [f"{ALLOWED_IP}/32"])

    def username_seen_from(ip: str):
        return requests.get(
            f"{url}/@warpgate/api/info",
            headers={"X-Warpgate-Token": token, "X-Forwarded-For": ip},
            verify=False,
        ).json()["username"]

    assert username_seen_from(ALLOWED_IP) == user.username
    assert username_seen_from(DENIED_IP) is None
