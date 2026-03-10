import html
import re
import requests
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .test_http_common import *  # noqa
from .util import alloc_port, wait_port


DEFAULT_OIDC_SCOPES = ["openid", "email", "profile", "preferred_username"]


def _make_sso_provider_config(
    oidc_port,
    *,
    auto_create_users=False,
    role_mappings=None,
    extra_scopes=None,
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
    return {
        "name": "test-oidc",
        "label": "OIDC Test",
        "provider": provider,
        "auto_create_users": auto_create_users,
    }


def _start_wg_with_oidc(processes, wg_http_port, oidc_port, **sso_kwargs):
    """Start a warpgate instance wired to the OIDC mock."""
    sso_config = _make_sso_provider_config(oidc_port, **sso_kwargs)
    wg = processes.start_wg(
        http_port=wg_http_port,
        config_patch={
            "external_host": "127.0.0.1",
            "sso_providers": [sso_config],
        },
    )
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    return wg


def _create_echo_target(api, echo_server_port, role_id):
    """Create an HTTP echo target and grant a role access."""
    target = api.create_target(
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
    api.add_target_role(target.id, role_id)
    return target


def _do_oidc_login(wg_url, oidc_port, *, username="User1", password="pwd"):
    """Drive the full OIDC authorization-code flow against the mock.

    Returns ``(wg_session, redirect_url)`` where *wg_session* carries the
    authenticated cookies and *redirect_url* is warpgate's SSO-return URL
    (already followed).
    """
    from urllib.parse import urlparse, parse_qs

    wg_session = requests.Session()
    wg_session.verify = False

    # Initiate SSO
    resp = wg_session.get(f"{wg_url}/@warpgate/api/sso/providers/test-oidc/start")
    assert resp.status_code == 200
    auth_url = resp.json()["url"]

    # Follow to OIDC mock login page
    oidc_session = requests.Session()
    resp = oidc_session.get(auth_url)
    assert resp.status_code == 200
    login_page_url = resp.url
    login_html = resp.text

    # Extract anti-forgery token (attribute order may vary)
    token_match = re.search(
        r'name="__RequestVerificationToken"[^>]*value="([^"]*)"',
        login_html,
    )
    if not token_match:
        token_match = re.search(
            r'value="([^"]*)"[^>]*name="__RequestVerificationToken"',
            login_html,
        )
    assert token_match, "Could not find __RequestVerificationToken in login form"
    verification_token = html.unescape(token_match.group(1))

    # The OIDC mock may use "Input.ReturnUrl" (Duende IdentityServer
    # convention) or plain "ReturnUrl".  Try both, then fall back to URL.
    return_url = None
    m = re.search(
        r'name="Input.ReturnUrl"[^>]*value="([^"]*)"',
        login_html,
    )
    assert m, "Could not find ReturnUrl in login form"
    return_url = html.unescape(m.group(1))

    # Detect whether the mock uses the "Input." field-name prefix
    uses_input_prefix = 'name="Input.' in login_html

    def _field(name):
        return f"Input.{name}" if uses_input_prefix else name

    # Submit credentials
    resp = oidc_session.post(
        login_page_url,
        data={
            _field("Username"): username,
            _field("Password"): password,
            _field("Button") if uses_input_prefix else "button": "login",
            _field("ReturnUrl"): return_url,
            "__RequestVerificationToken": verification_token,
        },
        allow_redirects=False,
    )

    # Chase redirects until we land back at warpgate's SSO return endpoint
    redirect_url = None
    for _ in range(15):
        if resp.status_code not in (301, 302, 303, 307, 308):
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

    # The OIDC redirect_uri uses 127.0.0.1 but we started the SSO flow on
    # wg_url (localhost).  Rewrite so the session cookies (set for localhost)
    # are sent with this request.
    parsed_redirect = urlparse(redirect_url)
    parsed_wg = urlparse(wg_url)
    redirect_url = redirect_url.replace(
        f"{parsed_redirect.scheme}://{parsed_redirect.netloc}",
        f"{parsed_wg.scheme}://{parsed_wg.netloc}",
        1,
    )

    # Complete the SSO flow on warpgate
    resp = wg_session.get(redirect_url, allow_redirects=False)
    return wg_session, resp


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestHTTPUserAuthOIDC:
    """Tests the full OIDC authorization code flow using a mock OIDC provider."""

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
            role_names = {r.name for r in user_roles}
            assert "role-keep" in role_names
            assert "role-remove" not in role_names
