import html
import json
import re
import socket
import requests
import pytest
from contextlib import contextmanager
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .test_http_common import *  # noqa
from .util import alloc_port, wait_port


DEFAULT_OIDC_SCOPES = ["openid", "email", "profile", "preferred_username"]


@contextmanager
def _resolve_hosts_to_localhost(*hosts):
    original_getaddrinfo = socket.getaddrinfo
    resolved_hosts = set(hosts)

    def getaddrinfo(host, *args, **kwargs):
        if host in resolved_hosts:
            return original_getaddrinfo("127.0.0.1", *args, **kwargs)
        return original_getaddrinfo(host, *args, **kwargs)

    socket.getaddrinfo = getaddrinfo
    try:
        yield
    finally:
        socket.getaddrinfo = original_getaddrinfo


def _make_sso_provider_config(
    oidc_port,
    *,
    auto_create_users=False,
    role_mappings=None,
    admin_role_mappings=None,
    extra_scopes=None,
    return_url_domain=None,
    roles_claim=None,
    admin_roles_claim=None,
):
    """Build an ``sso_providers`` entry for warpgate config."""
    scopes = list(DEFAULT_OIDC_SCOPES)
    if extra_scopes:
        scopes.extend(extra_scopes)
    provider = {
        "type": "custom",
        "client_id": "warpgate-test",
        "client_secret": "warpgate-test-secret",
        "issuer_url": f"http://localhost:{oidc_port}",
        "scopes": scopes,
    }
    if role_mappings is not None:
        provider["role_mappings"] = role_mappings
    if admin_role_mappings is not None:
        provider["admin_role_mappings"] = admin_role_mappings
    if roles_claim is not None:
        provider["roles_claim"] = roles_claim
    if admin_roles_claim is not None:
        provider["admin_roles_claim"] = admin_roles_claim
    sso_entry = {
        "name": "test-oidc",
        "label": "OIDC Test",
        "provider": provider,
        "auto_create_users": auto_create_users,
    }
    if return_url_domain is not None:
        sso_entry["return_url_domain"] = return_url_domain
    return sso_entry


def _start_wg_with_oidc(processes, wg_http_port, oidc_port, *, external_host="127.0.0.1", **sso_kwargs):
    """Start a warpgate instance wired to the OIDC mock."""
    sso_config = _make_sso_provider_config(oidc_port, **sso_kwargs)
    config_patch = {"sso_providers": [sso_config], "external_host": external_host}
    wg = processes.start_wg(
        http_port=wg_http_port,
        config_patch=config_patch,
    )
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    return wg


def _create_echo_target(api, echo_server_port, role_id, *, external_host=None):
    """Create an HTTP echo target and grant a role access."""
    target = api.create_target(
        sdk.TargetDataRequest(
            name=f"echo-{uuid4()}",
            options=sdk.TargetOptions(
                sdk.TargetOptionsTargetHTTPOptions(
                    kind="Http",
                    url=f"http://localhost:{echo_server_port}",
                    external_host=external_host,
                    tls=sdk.Tls(
                        mode=sdk.TlsMode.DISABLED,
                        verify=False,
                    ),
                )
            ),
        )
    )
    api.add_target_role(target.id, role_id)
    return target


def _session_cookie_domains(session):
    domains = set()
    for domain, paths in session.cookies._cookies.items():
        for cookies_by_name in paths.values():
            if "warpgate-http-session" in cookies_by_name:
                domains.add(domain)
    return domains


def _complete_oidc_login(
    wg_session, oidc_port, auth_url, *, username="User1", password="pwd"
):
    oidc_session = requests.Session()
    oidc_session.verify = False
    resp = oidc_session.get(auth_url)
    assert resp.status_code == 200
    login_page_url = resp.url
    login_html = resp.text

    # Extract anti-forgery token
    # These are oidc mock specific
    token_match = re.search(
        r'name="__RequestVerificationToken"[^>]*value="([^\"]*)"',
        login_html,
    )
    assert token_match, (
        f"Could not find __RequestVerificationToken in login form: {login_html[:500]}"
    )
    verification_token = html.unescape(token_match.group(1))

    action = login_page_url
    m = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', login_html, re.I)
    if m:
        action = m.group(1)
        if action.startswith("/"):
            action = f"http://localhost:{oidc_port}{action}"

    m = re.search(
        r'name="Input.ReturnUrl"[^>]*value="([^"]*)"',
        login_html,
    )
    assert m, "Could not find ReturnUrl in login form"
    return_url = html.unescape(m.group(1))

    resp = oidc_session.post(
        login_page_url,
        data={
            "Input.Username": username,
            "Input.Password": password,
            "Input.Button": "login",
            "Input.ReturnUrl": return_url,
            "__RequestVerificationToken": verification_token,
        },
        allow_redirects=False,
    )

    # Chase redirects until we land back at warpgate's SSO return endpoint
    redirect_url = None
    for _ in range(15):
        if resp.status_code // 100 != 3:
            break
        location = resp.headers["Location"]
        if location.startswith("/"):
            location = f"http://localhost:{oidc_port}{location}"
        if "/@warpgate/api/sso/return" in location:
            redirect_url = location
            break
        resp = oidc_session.get(location, allow_redirects=False)

    assert redirect_url is not None, (
        "OIDC mock did not redirect back to warpgate's SSO return endpoint"
    )
    assert "code=" in redirect_url, "Redirect URL missing authorization code"

    return wg_session, redirect_url


def _do_oidc_login(wg_url, oidc_port, *, username="User1", password="pwd"):
    """Drive the full OIDC authorization-code flow against the mock.

    Returns ``(wg_session, redirect_url)`` where *wg_session* carries the
    authenticated cookies and *redirect_url* is warpgate's SSO-return URL
    (already followed).
    """

    wg_session, redirect_url = _follow_oidc_login_redirects(
        wg_url, oidc_port, username=username, password=password
    )

    resp = wg_session.get(redirect_url, allow_redirects=False)
    return wg_session, resp


def _follow_oidc_login_redirects(
    wg_url, oidc_port, *, username="User1", password="pwd"
):
    """Drive the full OIDC authorization-code flow against the mock
    and return the final Warpgate return URL without actually requesting it"""

    wg_session = requests.Session()
    wg_session.verify = False

    # Initiate SSO
    resp = wg_session.get(f"{wg_url}/@warpgate/api/sso/providers/test-oidc/start")
    assert resp.status_code == 200
    auth_url = resp.json()["url"]
    return _complete_oidc_login(
        wg_session, oidc_port, auth_url, username=username, password=password
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestHTTPUserAuthOIDC:
    """Tests the full OIDC authorization code flow using a mock OIDC provider."""

    @pytest.mark.parametrize(
        "case",
        [
            # Login at external_host: SSO return URL pinned to external_host.
            dict(
                login_host="warpgate.acme.inc",
                return_url_domain="external_host",
                expected_return_host="warpgate.acme.inc",
            ),
            # Login at a subdomain with ExternalHost: return URL is still external_host.
            dict(
                login_host="target.warpgate.acme.inc",
                return_url_domain="external_host",
                expected_return_host="warpgate.acme.inc",
            ),
            # Login at a subdomain with HostHeader: return URL follows the request host.
            dict(
                login_host="target.warpgate.acme.inc",
                return_url_domain="host_header",
                expected_return_host="target.warpgate.acme.inc",
            ),
        ],
    )
    def test_oidc_cross_domain_cookie_and_return_url_domain(
        self,
        echo_server_port,
        processes: ProcessManager,
        case,
    ):
        login_host = case["login_host"]
        return_url_domain = case["return_url_domain"]
        expected_return_host = case["expected_return_host"]
        wg_http_port = alloc_port()
        redirect_uris = [
            f"https://{login_host}:{wg_http_port}/@warpgate/api/sso/return",
            f"https://{expected_return_host}:{wg_http_port}/@warpgate/api/sso/return",
        ]
        oidc_port = processes.start_oidc_server(
            wg_http_port,
            redirect_uris=redirect_uris,
        )
        wg = _start_wg_with_oidc(
            processes,
            wg_http_port,
            oidc_port,
            external_host="warpgate.acme.inc",
            return_url_domain=return_url_domain,
        )
        wg_url = f"https://{login_host}:{wg.http_port}"
        target_url = f"https://target.warpgate.acme.inc:{wg.http_port}"

        with _resolve_hosts_to_localhost(
            "warpgate.acme.inc",
            "target.warpgate.acme.inc",
        ):
            with admin_client(wg_url) as api:
                role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
                target = _create_echo_target(
                    api,
                    echo_server_port,
                    role.id,
                    external_host="target.warpgate.acme.inc",
                )
                user = api.create_user(
                    sdk.CreateUserRequest(username=f"user-{uuid4()}")
                )
                api.create_sso_credential(
                    user.id,
                    sdk.NewSsoCredential(
                        email="sam.tailor@gmail.com",
                        provider="test-oidc",
                    ),
                )
                api.add_user_role(user.id, role.id)

            session = requests.Session()
            session.verify = False
            start_resp = session.get(
                f"{wg_url}/@warpgate/api/sso/providers/test-oidc/start"
            )
            assert start_resp.status_code == 200, (
                f"Failed to start SSO: {start_resp.status_code} {start_resp.text[:500]}"
            )

            auth_url = start_resp.json()["url"]
            redirect_uri = parse_qs(urlparse(auth_url).query)["redirect_uri"][0]
            assert urlparse(redirect_uri).hostname == expected_return_host

            _, redirect_url = _complete_oidc_login(session, oidc_port, auth_url)
            callback_resp = session.get(redirect_url, allow_redirects=False)
            assert callback_resp.status_code in (302, 307)
            assert callback_resp.headers["Location"] == f"{wg_url}/@warpgate#/login"

            target_resp = session.get(
                f"{target_url}/some/path?warpgate-target={target.name}",
                allow_redirects=False,
            )
            assert target_resp.status_code // 100 == 2
            assert target_resp.json()["path"] == "/some/path"

    @pytest.mark.parametrize(
        "case",
        [
            # Login at external_host: cookie Domain=.warpgate.acme.inc so all subdomains inherit it.
            dict(
                login_host="warpgate.acme.inc",
                return_url_domain="external_host",
                expect_start_ok=True,
                cross_check_host="sub.warpgate.acme.inc",
                expect_cross_access=True,
            ),
            # Login at a subdomain: cookie Domain=.warpgate.acme.inc, valid at parent too.
            dict(
                login_host="sub.warpgate.acme.inc",
                return_url_domain="host_header",
                expect_start_ok=True,
                cross_check_host="warpgate.acme.inc",
                expect_cross_access=True,
            ),
            # Unrelated domain + external_host: IdP callback would reach external_host while
            # session lives on not-sub-domain.acme.inc — rejected early with HTTP 400.
            dict(
                login_host="not-sub-domain.acme.inc",
                return_url_domain="external_host",
                expect_start_ok=False,
                cross_check_host=None,
                expect_cross_access=False,
            ),
            # Unrelated domain + host_header: SSO completes, but session is scoped to
            # not-sub-domain.acme.inc only — not visible from warpgate.acme.inc.
            dict(
                login_host="not-sub-domain.acme.inc",
                return_url_domain="host_header",
                expect_start_ok=True,
                cross_check_host="warpgate.acme.inc",
                expect_cross_access=False,
            ),
        ],
    )
    def test_oidc_cookie_domain_flows(
        self,
        echo_server_port,
        processes: ProcessManager,
        case,
    ):
        login_host = case["login_host"]
        return_url_domain = case["return_url_domain"]
        expect_start_ok = case["expect_start_ok"]
        cross_check_host = case["cross_check_host"]
        expect_cross_access = case["expect_cross_access"]
        wg_http_port = alloc_port()
        redirect_uris = [
            f"https://warpgate.acme.inc:{wg_http_port}/@warpgate/api/sso/return",
            f"https://sub.warpgate.acme.inc:{wg_http_port}/@warpgate/api/sso/return",
            f"https://not-sub-domain.acme.inc:{wg_http_port}/@warpgate/api/sso/return",
        ]
        oidc_port = processes.start_oidc_server(
            wg_http_port,
            redirect_uris=redirect_uris,
        )
        wg = _start_wg_with_oidc(
            processes,
            wg_http_port,
            oidc_port,
            external_host="warpgate.acme.inc",
            return_url_domain=return_url_domain,
        )

        all_hosts = {
            "warpgate.acme.inc",
            "sub.warpgate.acme.inc",
            "not-sub-domain.acme.inc",
        }
        wg_url = f"https://{login_host}:{wg.http_port}"
        external_host_url = f"https://warpgate.acme.inc:{wg.http_port}"

        with _resolve_hosts_to_localhost(*all_hosts):
            with admin_client(external_host_url) as api:
                role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
                # Echo target has no external_host restriction so it is
                # reachable from any host via ?warpgate-target=.
                echo_target = _create_echo_target(api, echo_server_port, role.id)
                user = api.create_user(
                    sdk.CreateUserRequest(username=f"user-{uuid4()}")
                )
                api.create_sso_credential(
                    user.id,
                    sdk.NewSsoCredential(
                        email="sam.tailor@gmail.com",
                        provider="test-oidc",
                    ),
                )
                api.add_user_role(user.id, role.id)

            session = requests.Session()
            session.verify = False

            start_resp = session.get(
                f"{wg_url}/@warpgate/api/sso/providers/test-oidc/start"
            )

            if not expect_start_ok:
                # Incompatible domain: external_host ≠ login_host and no
                # subdomain relationship while return_url_domain=external_host.
                assert start_resp.status_code == 400
                return

            assert start_resp.status_code == 200
            auth_url = start_resp.json()["url"]

            _, redirect_url = _complete_oidc_login(session, oidc_port, auth_url)
            callback_resp = session.get(redirect_url, allow_redirects=False)
            assert callback_resp.status_code in (302, 307)

            # Verify the session cookie domain covers login_host.
            cookie_domains = _session_cookie_domains(session)
            assert cookie_domains, (
                "Expected at least one domain with the session cookie"
            )

            # Access the echo target from cross_check_host using the session
            assert cross_check_host is not None
            cross_url = f"https://{cross_check_host}:{wg.http_port}"
            cross_resp = session.get(
                f"{cross_url}/probe?warpgate-target={echo_target.name}",
                allow_redirects=False,
            )
            if expect_cross_access:
                assert cross_resp.status_code // 100 == 2, (
                    f"Expected authenticated access from {cross_check_host} "
                    f"(login was at {login_host}), got {cross_resp.status_code}"
                )
            else:
                assert cross_resp.status_code // 100 != 2, (
                    f"Expected session NOT to be shared with {cross_check_host} "
                    f"(login was at {login_host}), but got {cross_resp.status_code}"
                )

    def test_oidc_auth_flow(
        self,
        echo_server_port,
        processes: ProcessManager,
    ):
        wg_http_port = alloc_port()
        oidc_port = processes.start_oidc_server(wg_http_port)
        wg = _start_wg_with_oidc(processes, wg_http_port, oidc_port)
        wg_url = f"https://127.0.0.1:{wg.http_port}"

        with admin_client(wg_url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_sso_credential(
                user.id,
                sdk.NewSsoCredential(
                    email="sam.tailor@gmail.com",
                    provider="test-oidc",
                ),
            )
            api.add_user_role(user.id, role.id)
            echo_target = _create_echo_target(api, echo_server_port, role.id)

        # Verify SSO provider is listed
        wg_session = requests.Session()
        wg_session.verify = False
        resp = wg_session.get(f"{wg_url}/@warpgate/api/sso/providers")
        assert resp.status_code == 200
        assert any(p["name"] == "test-oidc" for p in resp.json())

        wg_session, resp = _do_oidc_login(wg_url, oidc_port)
        assert resp.status_code in (302, 307), (
            f"Expected redirect from SSO return, got {resp.status_code}: {resp.text[:500]}"
        )

        # Verify authenticated access to the echo target
        resp = wg_session.get(
            f"{wg_url}/some/path?a=b&warpgate-target={echo_target.name}&c=d",
            allow_redirects=False,
        )
        assert resp.status_code // 100 == 2
        assert resp.json()["path"] == "/some/path"

    def test_oidc_auth_rejects_invalid_state(
        self,
        echo_server_port,
        processes: ProcessManager,
    ):
        wg_http_port = alloc_port()
        oidc_port = processes.start_oidc_server(wg_http_port)
        wg = _start_wg_with_oidc(processes, wg_http_port, oidc_port)
        wg_url = f"https://127.0.0.1:{wg.http_port}"

        with admin_client(wg_url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_sso_credential(
                user.id,
                sdk.NewSsoCredential(
                    email="sam.tailor@gmail.com",
                    provider="test-oidc",
                ),
            )
            api.add_user_role(user.id, role.id)
            _create_echo_target(api, echo_server_port, role.id)

        wg_session, redirect_url = _follow_oidc_login_redirects(
            wg_url,
            oidc_port,
            username="User1",
            password="pwd",
        )

        parsed = urlparse(redirect_url)
        params = parse_qs(parsed.query)
        params["state"] = ["invalid-state"]
        redirect_url = urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                urlencode(params, doseq=True),
                parsed.fragment,
            )
        )

        resp = wg_session.get(redirect_url, allow_redirects=False)
        assert resp.status_code in (302, 307)
        assert "login_error" in resp.headers.get("Location", "")

    def test_oidc_auth_wrong_credentials(
        self,
        echo_server_port,
        processes: ProcessManager,
    ):
        wg_http_port = alloc_port()
        oidc_port = processes.start_oidc_server(wg_http_port)
        wg = _start_wg_with_oidc(processes, wg_http_port, oidc_port)
        wg_url = f"https://127.0.0.1:{wg.http_port}"

        with admin_client(wg_url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_sso_credential(
                user.id,
                sdk.NewSsoCredential(
                    email="wrong-email@example.com",
                    provider="test-oidc",
                ),
            )
            api.add_user_role(user.id, role.id)
            echo_target = _create_echo_target(api, echo_server_port, role.id)

        # Login with valid OIDC creds, but the mock user's email
        # (sam.tailor@gmail.com) doesn't match the SSO credential.
        wg_session, resp = _do_oidc_login(wg_url, oidc_port)
        assert resp.status_code in (302, 307)
        location = resp.headers.get("Location", "")
        assert "login_error" in location

        # Verify user is NOT authenticated
        resp = wg_session.get(
            f"{wg_url}/some/path?warpgate-target={echo_target.name}",
            allow_redirects=False,
        )
        assert resp.status_code // 100 != 2

    # -- User autocreation tests -------------------------------------------

    def test_oidc_auto_create_user(
        self,
        echo_server_port,
        processes: ProcessManager,
    ):
        wg_http_port = alloc_port()
        oidc_port = processes.start_oidc_server(wg_http_port)
        wg = _start_wg_with_oidc(
            processes, wg_http_port, oidc_port, auto_create_users=True
        )
        wg_url = f"https://127.0.0.1:{wg.http_port}"

        # Pre-create a role and target so the auto-created user can be granted
        # access after creation (we assign the role to the target but NOT to
        # any user yet).
        with admin_client(wg_url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            _create_echo_target(api, echo_server_port, role.id)

            # No users exist with this SSO credential yet
            users_before = api.get_users()

        wg_session, resp = _do_oidc_login(wg_url, oidc_port)
        assert resp.status_code in (302, 307), (
            f"Expected redirect after auto-creation, got {resp.status_code}"
        )

        # Verify the user was created with the preferred_username from OIDC
        with admin_client(wg_url) as api:
            users_after = api.get_users()
            new_users = [
                u
                for u in users_after
                if u.username not in {ub.username for ub in users_before}
            ]
            assert len(new_users) == 1, (
                f"Expected exactly 1 new user, found {len(new_users)}"
            )
            assert new_users[0].username == "sam_tailor"

    def test_oidc_auto_create_user_disabled(
        self,
        echo_server_port,
        processes: ProcessManager,
    ):
        """When auto_create_users is False (the default) and no matching SSO
        credential exists, the login should be rejected."""
        wg_http_port = alloc_port()
        oidc_port = processes.start_oidc_server(wg_http_port)
        wg = _start_wg_with_oidc(
            processes, wg_http_port, oidc_port, auto_create_users=False
        )
        wg_url = f"https://127.0.0.1:{wg.http_port}"

        # Don't create any user/SSO credential - login should fail
        wg_session, resp = _do_oidc_login(wg_url, oidc_port)
        assert resp.status_code in (302, 307)
        location = resp.headers.get("Location", "")
        assert "login_error" in location

    # -- Group sync / role mapping tests -----------------------------------

    def test_oidc_group_sync_with_role_mappings(
        self,
        echo_server_port,
        processes: ProcessManager,
    ):
        wg_http_port = alloc_port()

        # Configure mock user with warpgate_roles claims
        oidc_users = [
            {
                "SubjectId": "1",
                "Username": "User1",
                "Password": "pwd",
                "Claims": [
                    {"Type": "name", "Value": "Sam Tailor", "ValueType": "string"},
                    {
                        "Type": "email",
                        "Value": "sam.tailor@gmail.com",
                        "ValueType": "string",
                    },
                    {
                        "Type": "preferred_username",
                        "Value": "sam_tailor",
                        "ValueType": "string",
                    },
                    # The OIDC mock provides multiple claims with the same type
                    # for array values in userinfo.
                    {
                        "Type": "warpgate_roles",
                        "Value": "oidc-admins",
                        "ValueType": "string",
                    },
                    {
                        "Type": "warpgate_roles",
                        "Value": "oidc-viewers",
                        "ValueType": "string",
                    },
                ],
            }
        ]

        oidc_port = processes.start_oidc_server(
            wg_http_port,
            extra_scopes=["warpgate_roles"],
            users_override=oidc_users,
            extra_identity_resources=[
                {"Name": "warpgate_roles", "ClaimTypes": ["warpgate_roles"]},
            ],
        )

        # Map OIDC groups to warpgate role names
        role_mappings = {
            "oidc-admins": "wg-admin-role",
            "oidc-viewers": "wg-viewer-role",
        }

        wg = _start_wg_with_oidc(
            processes,
            wg_http_port,
            oidc_port,
            auto_create_users=True,
            role_mappings=role_mappings,
            extra_scopes=["warpgate_roles"],
        )
        wg_url = f"https://127.0.0.1:{wg.http_port}"

        with admin_client(wg_url) as api:
            # Pre-create the roles that the mapping targets
            admin_role = api.create_role(sdk.RoleDataRequest(name="wg-admin-role"))
            api.create_role(sdk.RoleDataRequest(name="wg-viewer-role"))
            # Also create a role that is NOT in the mapping (should not be
            # assigned)
            api.create_role(sdk.RoleDataRequest(name="wg-unrelated-role"))
            _create_echo_target(api, echo_server_port, admin_role.id)

        wg_session, resp = _do_oidc_login(wg_url, oidc_port)
        assert resp.status_code in (302, 307)

        # Verify the auto-created user has the mapped roles
        with admin_client(wg_url) as api:
            users = api.get_users()
            user = next(u for u in users if u.username == "sam_tailor")
            user_roles = api.get_user_roles(user.id)
            role_names = {r.name for r in user_roles}

            assert "wg-admin-role" in role_names
            assert "wg-viewer-role" in role_names
            assert "wg-unrelated-role" not in role_names

        # verify no admin roles yet
        admin_roles = api.get_user_admin_roles(user.id)
        assert admin_roles == []

    def test_oidc_group_sync_without_mappings(
        self,
        echo_server_port,
        processes: ProcessManager,
    ):
        """When no role_mappings are configured, warpgate_roles claim values
        are used directly as role names."""
        wg_http_port = alloc_port()

        oidc_users = [
            {
                "SubjectId": "1",
                "Username": "User1",
                "Password": "pwd",
                "Claims": [
                    {"Type": "name", "Value": "Sam Tailor", "ValueType": "string"},
                    {
                        "Type": "email",
                        "Value": "sam.tailor@gmail.com",
                        "ValueType": "string",
                    },
                    {
                        "Type": "preferred_username",
                        "Value": "sam_tailor",
                        "ValueType": "string",
                    },
                    {
                        "Type": "warpgate_roles",
                        "Value": "direct-role-a",
                        "ValueType": "string",
                    },
                    {
                        "Type": "warpgate_roles",
                        "Value": "direct-role-b",
                        "ValueType": "string",
                    },
                ],
            }
        ]

        oidc_port = processes.start_oidc_server(
            wg_http_port,
            extra_scopes=["warpgate_roles"],
            users_override=oidc_users,
            extra_identity_resources=[
                {"Name": "warpgate_roles", "ClaimTypes": ["warpgate_roles"]},
            ],
        )

        wg = _start_wg_with_oidc(
            processes,
            wg_http_port,
            oidc_port,
            auto_create_users=True,
            extra_scopes=["warpgate_roles"],
        )
        wg_url = f"https://127.0.0.1:{wg.http_port}"

        with admin_client(wg_url) as api:
            role_a = api.create_role(sdk.RoleDataRequest(name="direct-role-a"))
            api.create_role(sdk.RoleDataRequest(name="direct-role-b"))
            _create_echo_target(api, echo_server_port, role_a.id)

        wg_session, resp = _do_oidc_login(wg_url, oidc_port)
        assert resp.status_code in (302, 307)

        with admin_client(wg_url) as api:
            users = api.get_users()
            user = next(u for u in users if u.username == "sam_tailor")
            user_roles = api.get_user_roles(user.id)
            role_names = {r.name for r in user_roles}

            assert "direct-role-a" in role_names
            assert "direct-role-b" in role_names

            # admin role import without mappings
            admin_roles = api.get_user_admin_roles(user.id)
            assert admin_roles == []

    def test_oidc_group_sync_removes_stale_roles(
        self,
        echo_server_port,
        processes: ProcessManager,
    ):
        """On subsequent logins, roles that are no longer present in the OIDC
        warpgate_roles claim should be removed."""
        wg_http_port = alloc_port()

        # First login: user has both roles
        oidc_users_both = [
            {
                "SubjectId": "1",
                "Username": "User1",
                "Password": "pwd",
                "Claims": [
                    {"Type": "name", "Value": "Sam Tailor", "ValueType": "string"},
                    {
                        "Type": "email",
                        "Value": "sam.tailor@gmail.com",
                        "ValueType": "string",
                    },
                    {
                        "Type": "preferred_username",
                        "Value": "sam_tailor",
                        "ValueType": "string",
                    },
                    {
                        "Type": "warpgate_roles",
                        "Value": "role-keep",
                        "ValueType": "string",
                    },
                    {
                        "Type": "warpgate_roles",
                        "Value": "role-remove",
                        "ValueType": "string",
                    },
                ],
            }
        ]

        oidc_port = processes.start_oidc_server(
            wg_http_port,
            extra_scopes=["warpgate_roles"],
            users_override=oidc_users_both,
            extra_identity_resources=[
                {"Name": "warpgate_roles", "ClaimTypes": ["warpgate_roles"]},
            ],
        )

        wg = _start_wg_with_oidc(
            processes,
            wg_http_port,
            oidc_port,
            auto_create_users=True,
            extra_scopes=["warpgate_roles"],
        )
        wg_url = f"https://127.0.0.1:{wg.http_port}"

        with admin_client(wg_url) as api:
            api.create_role(sdk.RoleDataRequest(name="role-keep"))
            role_rm = api.create_role(sdk.RoleDataRequest(name="role-remove"))
            _create_echo_target(api, echo_server_port, role_rm.id)

        # First login — user gets both roles
        _, resp = _do_oidc_login(wg_url, oidc_port)
        assert resp.status_code in (302, 307)

        with admin_client(wg_url) as api:
            users = api.get_users()
            user = next(u for u in users if u.username == "sam_tailor")
            role_names = {r.name for r in api.get_user_roles(user.id)}
            assert "role-keep" in role_names
            assert "role-remove" in role_names

        # Second login: start a new OIDC mock where the user only has
        # "role-keep".  We need a fresh mock because the mock server's user
        # config is fixed at startup.
        wg_http_port2 = alloc_port()
        oidc_users_reduced = [
            {
                "SubjectId": "1",
                "Username": "User1",
                "Password": "pwd",
                "Claims": [
                    {"Type": "name", "Value": "Sam Tailor", "ValueType": "string"},
                    {
                        "Type": "email",
                        "Value": "sam.tailor@gmail.com",
                        "ValueType": "string",
                    },
                    {
                        "Type": "preferred_username",
                        "Value": "sam_tailor",
                        "ValueType": "string",
                    },
                    {
                        "Type": "warpgate_roles",
                        "Value": "role-keep",
                        "ValueType": "string",
                    },
                ],
            }
        ]

        oidc_port2 = processes.start_oidc_server(
            wg_http_port2,
            extra_scopes=["warpgate_roles"],
            users_override=oidc_users_reduced,
            extra_identity_resources=[
                {"Name": "warpgate_roles", "ClaimTypes": ["warpgate_roles"]},
            ],
        )

        wg2 = _start_wg_with_oidc(
            processes,
            wg_http_port2,
            oidc_port2,
            auto_create_users=True,
            extra_scopes=["warpgate_roles"],
        )
        wg_url2 = f"https://127.0.0.1:{wg2.http_port}"

        # The user already exists from the first wg instance's DB, but this is
        # a fresh warpgate with its own DB.  Re-create the user so we can test
        # the role-removal path.
        with admin_client(wg_url2) as api:
            api.create_role(sdk.RoleDataRequest(name="role-keep"))
            api.create_role(sdk.RoleDataRequest(name="role-remove"))
            user = api.create_user(sdk.CreateUserRequest(username="sam_tailor"))
            api.create_sso_credential(
                user.id,
                sdk.NewSsoCredential(
                    email="sam.tailor@gmail.com",
                    provider="test-oidc",
                ),
            )
            # Pre-assign both roles
            roles = api.get_roles()
            for r in roles:
                if r.name in ("role-keep", "role-remove"):
                    api.add_user_role(user.id, r.id)

        _, resp = _do_oidc_login(wg_url2, oidc_port2)
        assert resp.status_code in (302, 307)

        with admin_client(wg_url2) as api:
            user_roles = api.get_user_roles(user.id)
            active_role_names = {r.name for r in user_roles if r.is_active}
            assert "role-keep" in active_role_names
            assert "role-remove" not in active_role_names


# ---------------------------------------------------------------------------
# `groups_claim`: source group memberships from a configurable OIDC claim
# (e.g. the standard-ish `groups` claim) and map them to roles via
# role_mappings / admin_role_mappings. Group names are generic placeholders.
# ---------------------------------------------------------------------------

def _user_with_group_claims(entries):
    """Build a single OIDC mock user whose `groups` claim is built from
    *entries* (a list of ``{"Value":..., "ValueType":...}`` dicts)."""
    claims = [
        {"Type": "name", "Value": "Sam Tailor", "ValueType": "string"},
        {"Type": "email", "Value": "sam.tailor@gmail.com", "ValueType": "string"},
        {"Type": "preferred_username", "Value": "sam_tailor", "ValueType": "string"},
    ]
    for e in entries:
        claims.append({"Type": "groups", **e})
    return [
        {"SubjectId": "1", "Username": "User1", "Password": "pwd", "Claims": claims}
    ]


def _str_groups(*names):
    """Emit each group name as a repeated string-valued `groups` claim
    (the OIDC mock's representation of an array of strings)."""
    return [{"Value": n, "ValueType": "string"} for n in names]


def _json_groups(value):
    """Emit a single JSON-valued `groups` claim (array of strings/objects)."""
    return [{"Value": json.dumps(value), "ValueType": "json"}]


def _run_roles_claim_test(
    processes,
    group_entries,
    *,
    role_mappings=None,
    admin_role_mappings=None,
    pre_create_roles=(),
):
    """Drive a full OIDC login with a configurable `groups` claim and return
    ``(access_role_names, admin_role_names)`` for the auto-created user."""
    wg_http_port = alloc_port()
    oidc_port = processes.start_oidc_server(
        wg_http_port,
        extra_scopes=["groups"],
        users_override=_user_with_group_claims(group_entries),
        extra_identity_resources=[{"Name": "groups", "ClaimTypes": ["groups"]}],
    )
    wg = _start_wg_with_oidc(
        processes,
        wg_http_port,
        oidc_port,
        auto_create_users=True,
        roles_claim="groups",
        admin_roles_claim="groups",
        role_mappings=role_mappings,
        admin_role_mappings=admin_role_mappings,
        extra_scopes=["groups"],
    )
    wg_url = f"https://127.0.0.1:{wg.http_port}"

    with admin_client(wg_url) as api:
        for rn in pre_create_roles:
            api.create_role(sdk.RoleDataRequest(name=rn))

    _, resp = _do_oidc_login(wg_url, oidc_port)
    assert resp.status_code in (302, 307), (
        f"Expected redirect after login, got {resp.status_code}: {resp.text[:300]}"
    )

    with admin_client(wg_url) as api:
        user = next(u for u in api.get_users() if u.username == "sam_tailor")
        access = sorted(r.name for r in api.get_user_roles(user.id))
        admin = sorted(r.name for r in api.get_user_admin_roles(user.id))
    return access, admin


class TestHTTPUserAuthOIDCGroupsClaim:
    """Group memberships sourced from a configurable `groups` claim and mapped
    to access/admin roles via role_mappings / admin_role_mappings."""

    def test_access_role_mapping(self, echo_server_port, processes: ProcessManager):
        access, admin = _run_roles_claim_test(
            processes,
            _str_groups("grp-ssh"),
            role_mappings={"grp-ssh": "ssh-access-role"},
            pre_create_roles=["ssh-access-role"],
        )
        assert access == ["ssh-access-role"]
        assert admin == []

    def test_admin_role_mapping(self, echo_server_port, processes: ProcessManager):
        # "warpgate:admin" is warpgate's built-in admin role (always present).
        access, admin = _run_roles_claim_test(
            processes,
            _str_groups("grp-admin"),
            admin_role_mappings={"grp-admin": "warpgate:admin"},
        )
        assert access == []
        assert "warpgate:admin" in admin

    def test_combined_access_and_admin(
        self, echo_server_port, processes: ProcessManager
    ):
        access, admin = _run_roles_claim_test(
            processes,
            _str_groups("grp-admin", "grp-ssh"),
            role_mappings={"grp-ssh": "ssh-access-role"},
            admin_role_mappings={"grp-admin": "warpgate:admin"},
            pre_create_roles=["ssh-access-role"],
        )
        assert access == ["ssh-access-role"]
        assert "warpgate:admin" in admin

    def test_group_name_with_spaces(
        self, echo_server_port, processes: ProcessManager
    ):
        access, admin = _run_roles_claim_test(
            processes,
            _str_groups("remote ssh users"),
            role_mappings={"remote ssh users": "ssh-access-role"},
            pre_create_roles=["ssh-access-role"],
        )
        assert access == ["ssh-access-role"]

    def test_duplicate_group_names_dedup(
        self, echo_server_port, processes: ProcessManager
    ):
        access, admin = _run_roles_claim_test(
            processes,
            _str_groups("grp-ssh", "grp-ssh"),
            role_mappings={"grp-ssh": "ssh-access-role"},
            pre_create_roles=["ssh-access-role"],
        )
        # role assigned exactly once despite the duplicate group
        assert access == ["ssh-access-role"]

    def test_multiple_groups_some_unmapped(
        self, echo_server_port, processes: ProcessManager
    ):
        access, admin = _run_roles_claim_test(
            processes,
            _str_groups("grp-ssh", "grp-admin", "grp-extra", "grp-noise"),
            role_mappings={"grp-ssh": "ssh-access-role"},
            admin_role_mappings={"grp-admin": "warpgate:admin"},
            pre_create_roles=["ssh-access-role"],
        )
        assert access == ["ssh-access-role"]
        assert "warpgate:admin" in admin

    def test_mapping_by_group_id_object(
        self, echo_server_port, processes: ProcessManager
    ):
        # SCIM-style object array; map on the stable `value` (id), not the name.
        access, admin = _run_roles_claim_test(
            processes,
            _json_groups([{"value": "id-ssh", "display": "grp-ssh"}]),
            role_mappings={"id-ssh": "ssh-access-role"},
            pre_create_roles=["ssh-access-role"],
        )
        assert access == ["ssh-access-role"]

    def test_mapping_by_id_and_name_mixed(
        self, echo_server_port, processes: ProcessManager
    ):
        access, admin = _run_roles_claim_test(
            processes,
            _json_groups(
                [
                    {"value": "id-ssh", "display": "grp-ssh"},
                    {"value": "id-admin", "display": "grp-admin"},
                ]
            ),
            role_mappings={"id-ssh": "ssh-access-role"},  # by id
            admin_role_mappings={"grp-admin": "warpgate:admin"},  # by name
            pre_create_roles=["ssh-access-role"],
        )
        assert access == ["ssh-access-role"]
        assert "warpgate:admin" in admin

    def test_complex_objects_cross_dedup_and_spaces(
        self, echo_server_port, processes: ProcessManager
    ):
        # value/display collisions across entries, a value with a space, and a
        # string entry equal to another entry's display. Flattened set is:
        #   bla, bla2, dis1, dis2, val 3, val1, val2
        access, admin = _run_roles_claim_test(
            processes,
            _json_groups(
                [
                    "bla",
                    {"value": "val1", "display": "dis1"},
                    {"value": "val2", "display": "dis1"},
                    {"value": "val1", "display": "dis2"},
                    "bla2",
                    {"value": "val 3", "display": "bla2"},
                ]
            ),
            # map several flattened keys; "dis1" (shared display) and "bla2"
            # (string + display) must each yield their role exactly once.
            role_mappings={
                "dis1": "ssh-access-role",
                "val 3": "spaced-role",
            },
            admin_role_mappings={"bla2": "warpgate:admin"},
            pre_create_roles=["ssh-access-role", "spaced-role"],
        )
        assert access == ["spaced-role", "ssh-access-role"]
        assert "warpgate:admin" in admin
