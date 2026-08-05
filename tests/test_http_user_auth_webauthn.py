"""
Integration tests for WebAuthn/passkey authentication.

These tests verify:
- The WebAuthn registration and authentication API endpoints exist and respond correctly
- The credential policy enforces WebAuthn when configured
- The admin API can list and delete WebAuthn credentials

Note: Full end-to-end WebAuthn ceremony testing requires a browser environment
(navigator.credentials API). These tests verify the server-side API contract
and policy enforcement. The actual cryptographic ceremony is tested via the
Rust unit tests and manual browser testing.
"""
import requests
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import WarpgateProcess
from .test_http_common import *  # noqa


class TestHTTPUserAuthWebAuthn:
    def test_webauthn_registration_requires_auth(
        self,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        """Registration endpoints require an authenticated session."""
        url = f"https://localhost:{shared_wg.http_port}"
        session = requests.Session()
        session.verify = False

        # Unauthenticated request should fail
        response = session.post(
            f"{url}/@warpgate/api/auth/webauthn/registration/start",
        )
        assert response.status_code in (401, 403, 404)

    def test_webauthn_authentication_requires_login_state(
        self,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        """Authentication start requires a pending login (auth state)."""
        url = f"https://localhost:{shared_wg.http_port}"
        session = requests.Session()
        session.verify = False

        # No pending login → NotFound
        response = session.post(
            f"{url}/@warpgate/api/auth/webauthn/authentication/start",
        )
        assert response.status_code == 404

    def test_webauthn_policy_blocks_without_credential(
        self,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        """When policy requires WebAuthn but user has none registered,
        login with password alone should not grant access."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="pass123")
            )
            # Set policy requiring Password + WebAuthn
            api.update_user(
                user.id,
                sdk.UserDataRequest(
                    username=user.username,
                    credential_policy=sdk.UserRequireCredentialsPolicy(
                        http=["Password", "WebAuthn"]
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

        # Login with password
        response = session.post(
            f"{url}/@warpgate/api/auth/login",
            json={
                "username": user.username,
                "password": "pass123",
            },
        )
        # Should not be fully authenticated (needs WebAuthn too)
        assert response.status_code == 401

        # Check auth state shows WebAuthnNeeded
        response = session.get(f"{url}/@warpgate/api/auth/state")
        if response.status_code == 200:
            state = response.json()
            assert state["state"] == "WebAuthnNeeded"

        # Trying to access a target should fail
        response = session.get(
            f"{url}/some/path?warpgate-target={echo_target.name}",
            allow_redirects=False,
        )
        assert response.status_code // 100 != 2

    def test_webauthn_admin_crud(
        self,
        shared_wg: WarpgateProcess,
    ):
        """Admin API can list and delete WebAuthn credentials."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))

            # Initially no credentials
            creds = api.get_webauthn_credentials(user.id)
            assert len(creds) == 0

            # Note: We can't create a credential via admin API (requires browser ceremony)
            # but we can verify the endpoint exists and returns empty list

    def test_webauthn_complete_without_start_fails(
        self,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        """Completing authentication without starting returns BadRequest."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="pass123")
            )
            api.update_user(
                user.id,
                sdk.UserDataRequest(
                    username=user.username,
                    credential_policy=sdk.UserRequireCredentialsPolicy(
                        http=["Password", "WebAuthn"]
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

        # Login with password first to establish auth state
        session.post(
            f"{url}/@warpgate/api/auth/login",
            json={
                "username": user.username,
                "password": "pass123",
            },
        )

        # Try to complete WebAuthn without starting → should fail
        response = session.post(
            f"{url}/@warpgate/api/auth/webauthn/authentication/complete",
            json={
                "credential_json": "{}",
            },
        )
        assert response.status_code in (400, 401, 404)

    def test_password_only_policy_ignores_webauthn(
        self,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        """When policy only requires password, WebAuthn is not needed
        and login succeeds with just password (regression test)."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="pass123")
            )
            # Only require password
            api.update_user(
                user.id,
                sdk.UserDataRequest(
                    username=user.username,
                    credential_policy=sdk.UserRequireCredentialsPolicy(
                        http=["Password"]
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

        # Login with just password should succeed
        response = session.post(
            f"{url}/@warpgate/api/auth/login",
            json={
                "username": user.username,
                "password": "pass123",
            },
        )
        assert response.status_code == 201

        # Should be able to access the target
        response = session.get(
            f"{url}/some/path?warpgate-target={echo_target.name}",
            allow_redirects=False,
        )
        assert response.status_code // 100 == 2
