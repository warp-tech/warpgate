"""Cookie authority for the Warpgate surface: other sites and host-bound
target pages share the session cookie (`Domain=.<external_host>`), so they
must not be able to use it on the admin and user APIs."""

import requests
import pytest
from uuid import uuid4

from .api_client import admin_client, sdk
from .approval_util import NO_ADMIN_PERMISSIONS, create_password_user
from .conftest import ProcessManager
from .test_http_common import *  # noqa
from .test_http_user_auth_oidc import _create_echo_target, _resolve_hosts_to_localhost
from .util import wait_port

CONTROL_PLANE = "warpgate.acme.inc"
TARGET_HOST = f"t.{CONTROL_PLANE}"
NAVIGATION = {"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}


@pytest.fixture(scope="module")
def wg(processes: ProcessManager):
    wg = processes.start_wg(config_patch={"external_host": CONTROL_PLANE})
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    with _resolve_hosts_to_localhost(CONTROL_PLANE, TARGET_HOST):
        yield wg


def _url(host, port):
    return f"https://{host}:{port}"


def _login(host, port, username):
    session = requests.Session()
    session.verify = False
    resp = session.post(
        f"{_url(host, port)}/@warpgate/api/auth/login",
        json={"username": username, "password": "123"},
        headers={"Origin": _url(host, port), "Sec-Fetch-Site": "same-origin"},
    )
    assert resp.status_code // 100 == 2, resp.text
    return session


@pytest.fixture(scope="module")
def setup(wg, echo_server_port):
    cp = _url(CONTROL_PLANE, wg.http_port)
    with admin_client(cp) as api:
        admin, role = create_password_user(api)
        builtin = next(r for r in api.get_admin_roles() if r.name == "warpgate:admin")
        api.add_user_admin_role(admin.id, builtin.id)
        victim, _ = create_password_user(api)
        target = _create_echo_target(
            api, echo_server_port, role.id, external_host=TARGET_HOST
        )
    return dict(admin=admin, victim=victim, role=role, builtin=builtin, target=target)


def _grant(session, host, port, setup, headers):
    """The reporter's body-less escalation request."""
    return session.post(
        f"{_url(host, port)}/@warpgate/admin/api/users/"
        f"{setup['victim'].id}/admin-roles/{setup['builtin'].id}",
        headers={"Content-Type": "application/x-www-form-urlencoded", **headers},
    )


class TestHttpCsrf:
    @pytest.mark.parametrize(
        "host,headers",
        [
            (CONTROL_PLANE, {"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"}),
            (CONTROL_PLANE, {"Referer": "https://evil.example/page"}),
            # A host-bound target's page posting to the control plane.
            (CONTROL_PLANE, {"Origin": "TARGET", "Sec-Fetch-Site": "same-site"}),
            # A host-bound target's page using the Warpgate surface on its own host.
            (TARGET_HOST, {"Origin": "TARGET", "Sec-Fetch-Site": "same-origin"}),
        ],
    )
    def test_untrusted_page_cannot_use_admin_api(self, wg, setup, host, headers):
        headers = {
            k: _url(TARGET_HOST, wg.http_port) if v == "TARGET" else v
            for k, v in headers.items()
        }
        session = _login(CONTROL_PLANE, wg.http_port, setup["admin"].username)
        assert _grant(session, host, wg.http_port, setup, headers).status_code == 401

        with admin_client(_url(CONTROL_PLANE, wg.http_port)) as api:
            roles = api.get_user_admin_roles(setup["victim"].id)
        assert setup["builtin"].id not in [r.id for r in roles]

    def test_target_host_reads_and_bootstrap(self, wg, setup):
        session = _login(CONTROL_PLANE, wg.http_port, setup["admin"].username)
        target = _url(TARGET_HOST, wg.http_port)

        assert session.get(f"{target}/@warpgate/admin/api/users").status_code == 401
        assert session.get(f"{target}/@warpgate/api/targets").status_code == 401

        info = session.get(f"{target}/@warpgate/api/info")
        assert info.status_code == 200
        assert info.json()["username"] == setup["admin"].username
        assert info.json()["control_plane_host"] == CONTROL_PLANE

        resp = session.get(f"{target}/probe", allow_redirects=False)
        assert resp.status_code // 100 == 2, resp.text
        assert resp.json()["path"] == "/probe"

        resp = session.post(
            f"{target}/@warpgate/api/auth/logout",
            headers={"Origin": target, "Sec-Fetch-Site": "same-origin"},
        )
        assert resp.status_code // 100 == 2
        info = session.get(f"{_url(CONTROL_PLANE, wg.http_port)}/@warpgate/api/info")
        assert info.json()["username"] is None

    def test_control_plane_same_origin_allowed(self, wg, setup):
        cp = _url(CONTROL_PLANE, wg.http_port)
        session = _login(CONTROL_PLANE, wg.http_port, setup["admin"].username)
        users = session.get(f"{cp}/@warpgate/admin/api/users")
        assert users.status_code == 200

        with admin_client(cp) as api:
            role = api.create_admin_role(
                sdk.AdminRoleDataRequest(name=f"csrf-{uuid4()}", **NO_ADMIN_PERMISSIONS)
            )
        resp = session.post(
            f"{cp}/@warpgate/admin/api/users/{setup['victim'].id}/admin-roles/{role.id}",
            headers={"Origin": cp, "Sec-Fetch-Site": "same-origin"},
        )
        assert resp.status_code == 201, resp.text

    def test_logged_out_login_on_target_host(self, wg, setup):
        target = _url(TARGET_HOST, wg.http_port)
        session = requests.Session()
        session.verify = False

        resp = session.get(f"{target}/app", headers=NAVIGATION, allow_redirects=False)
        assert resp.status_code == 307
        assert resp.headers["Location"].startswith("/@warpgate#/login?next=")

        session = _login(TARGET_HOST, wg.http_port, setup["admin"].username)
        resp = session.get(f"{target}/app", allow_redirects=False)
        assert resp.status_code // 100 == 2, resp.text


class TestHttpCsrfMfaGate:
    def test_mfa_enrolment_from_target_host(self, wg, setup):
        cp = _url(CONTROL_PLANE, wg.http_port)
        target = _url(TARGET_HOST, wg.http_port)
        with admin_client(cp) as api:
            user, _ = create_password_user(api)
            api.add_user_role(user.id, setup["role"].id)
            api.update_parameters(
                sdk.ParameterUpdate(mfa_enforcement=sdk.MfaEnforcement.ENROLL)
            )
        try:
            session = _login(TARGET_HOST, wg.http_port, user.username)

            resp = session.get(f"{target}/app", headers=NAVIGATION, allow_redirects=False)
            assert resp.status_code == 307
            assert resp.headers["Location"] == "/@warpgate#/mfa-setup"

            info = session.get(f"{target}/@warpgate/api/info").json()
            assert info["needs_mfa_setup"] is True
            assert info["control_plane_host"] == CONTROL_PLANE

            resp = session.post(
                f"{cp}/@warpgate/api/profile/credentials/otp",
                json={"secret_key": list(range(20))},
                headers={"Origin": cp, "Sec-Fetch-Site": "same-origin"},
            )
            assert resp.status_code // 100 == 2, resp.text

            resp = session.get(f"{target}/app", allow_redirects=False)
            assert resp.status_code // 100 == 2, resp.text
        finally:
            with admin_client(cp) as api:
                api.update_parameters(
                    sdk.ParameterUpdate(mfa_enforcement=sdk.MfaEnforcement.OFF)
                )
