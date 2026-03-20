import requests
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import WarpgateProcess
from .test_http_common import *  # noqa


def _default_params(**overrides):
    """Build a ParameterUpdate with sensible defaults for self-service tests."""
    defaults = dict(
        allow_own_credential_management=True,
        minimize_password_login=False,
        rate_limit_bytes_per_second=None,
        ssh_client_auth_keyboard_interactive=True,
        ssh_client_auth_password=True,
        ssh_client_auth_publickey=True,
        ticket_self_service_enabled=False,
        ticket_auto_approve_existing_access=True,
        ticket_require_description=False,
    )
    defaults.update(overrides)
    return sdk.ParameterUpdate(**defaults)


def _disable_self_service(url):
    """Reset self-service to disabled state."""
    with admin_client(url) as api:
        api.update_parameters(_default_params(ticket_self_service_enabled=False))


class TestTicketRequests:
    def _setup_user_and_target(self, api, echo_server_port):
        """Create a user with role-based access to an HTTP target."""
        role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        api.create_password_credential(
            user.id, sdk.NewPasswordCredential(password="123")
        )
        api.add_user_role(user.id, role.id)
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
        api.add_target_role(target.id, role.id)
        return user, target, role

    def _login(self, url, username, password="123"):
        session = requests.Session()
        session.verify = False
        resp = session.post(
            f"{url}/@warpgate/api/auth/login",
            json={"username": username, "password": password},
        )
        assert resp.status_code // 100 == 2
        return session

    def test_self_service_disabled_by_default(
        self,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        """Ticket requests should fail when self-service is not enabled."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, target, role = self._setup_user_and_target(api, echo_server_port)

        session = self._login(url, user.username)
        resp = session.post(
            f"{url}/@warpgate/api/ticket-requests",
            json={
                "target_name": target.name,
                "description": "test",
            },
        )
        assert resp.status_code == 400

    def test_self_service_auto_approve(
        self,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        """When self-service is enabled and user has access, request auto-approves."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, target, role = self._setup_user_and_target(api, echo_server_port)
            api.update_parameters(_default_params(
                ticket_self_service_enabled=True,
                ticket_auto_approve_existing_access=True,
            ))

        try:
            session = self._login(url, user.username)
            resp = session.post(
                f"{url}/@warpgate/api/ticket-requests",
                json={
                    "target_name": target.name,
                    "description": "auto approve test",
                },
            )
            assert resp.status_code == 201
            data = resp.json()
            assert data["request"]["status"] == "Approved"
            assert data["secret"] is not None

            # The auto-approved ticket should work for HTTP access
            secret = data["secret"]
            verify_session = requests.Session()
            verify_session.verify = False
            resp = verify_session.get(
                f"{url}/some/path?warpgate-target={target.name}",
                headers={"Authorization": f"Warpgate {secret}"},
                allow_redirects=False,
            )
            assert resp.status_code // 100 == 2

            # List my requests
            resp = session.get(f"{url}/@warpgate/api/ticket-requests")
            assert resp.status_code == 200
            reqs = resp.json()
            assert any(r["target_name"] == target.name for r in reqs)

            # List my tickets
            resp = session.get(f"{url}/@warpgate/api/my-tickets")
            assert resp.status_code == 200
            tickets = resp.json()
            assert any(t["target"] == target.name for t in tickets)
            # Secret should NOT be in list response
            for t in tickets:
                assert "secret" not in t or t.get("secret") is None
        finally:
            _disable_self_service(url)

    def test_self_service_pending_approval(
        self,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        """When auto-approve is off, request stays pending until admin approves."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, target, role = self._setup_user_and_target(api, echo_server_port)
            api.update_parameters(_default_params(
                ticket_self_service_enabled=True,
                ticket_auto_approve_existing_access=False,
            ))

        try:
            session = self._login(url, user.username)
            resp = session.post(
                f"{url}/@warpgate/api/ticket-requests",
                json={
                    "target_name": target.name,
                    "description": "need access for testing",
                },
            )
            assert resp.status_code == 201
            data = resp.json()
            assert data["request"]["status"] == "Pending"
            assert data["secret"] is None
            request_id = data["request"]["id"]

            # Admin approves via admin API
            with admin_client(url) as api:
                result = api.approve_ticket_request(request_id)
                assert result.request.status == "Approved"
                assert result.secret is not None
                secret = result.secret

            # The approved ticket should work
            verify_session = requests.Session()
            verify_session.verify = False
            resp = verify_session.get(
                f"{url}/some/path?warpgate-target={target.name}",
                headers={"Authorization": f"Warpgate {secret}"},
                allow_redirects=False,
            )
            assert resp.status_code // 100 == 2
        finally:
            _disable_self_service(url)

    def test_self_service_deny(
        self,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        """Admin can deny a ticket request with a reason."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, target, role = self._setup_user_and_target(api, echo_server_port)
            api.update_parameters(_default_params(
                ticket_self_service_enabled=True,
                ticket_auto_approve_existing_access=False,
            ))

        try:
            session = self._login(url, user.username)
            resp = session.post(
                f"{url}/@warpgate/api/ticket-requests",
                json={
                    "target_name": target.name,
                    "description": "request that will be denied",
                },
            )
            assert resp.status_code == 201
            request_id = resp.json()["request"]["id"]

            # Admin denies
            with admin_client(url) as api:
                result = api.deny_ticket_request(
                    request_id,
                    sdk.DenyTicketRequestBody(reason="not authorized for this"),
                )
                assert result.status == "Denied"
                assert result.deny_reason == "not authorized for this"

            # User can see the denied status
            resp = session.get(f"{url}/@warpgate/api/ticket-requests")
            assert resp.status_code == 200
            denied = [r for r in resp.json() if r["id"] == request_id]
            assert len(denied) == 1
            assert denied[0]["status"] == "Denied"
            assert denied[0]["deny_reason"] == "not authorized for this"
        finally:
            _disable_self_service(url)

    def test_description_required(
        self,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        """When require_description is on, requests without description fail."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, target, role = self._setup_user_and_target(api, echo_server_port)
            api.update_parameters(_default_params(
                ticket_self_service_enabled=True,
                ticket_auto_approve_existing_access=True,
                ticket_require_description=True,
            ))

        try:
            session = self._login(url, user.username)

            # Empty description should fail with 400
            resp = session.post(
                f"{url}/@warpgate/api/ticket-requests",
                json={
                    "target_name": target.name,
                },
            )
            assert resp.status_code == 400

            # With description should succeed
            resp = session.post(
                f"{url}/@warpgate/api/ticket-requests",
                json={
                    "target_name": target.name,
                    "description": "valid reason",
                },
            )
            assert resp.status_code == 201
        finally:
            _disable_self_service(url)

    def test_admin_list_filter(
        self,
        shared_wg: WarpgateProcess,
    ):
        """Admin can list and filter ticket requests by status."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            # List all
            all_requests = api.get_ticket_requests()
            assert isinstance(all_requests, list)

            # Filter by status
            pending = api.get_ticket_requests(status="Pending")
            assert isinstance(pending, list)
            for r in pending:
                assert r.status == "Pending"

    def test_revoke_self_service_ticket(
        self,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        """User can revoke their own self-service tickets."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, target, role = self._setup_user_and_target(api, echo_server_port)
            api.update_parameters(_default_params(
                ticket_self_service_enabled=True,
                ticket_auto_approve_existing_access=True,
            ))

        try:
            session = self._login(url, user.username)

            # Create a ticket
            resp = session.post(
                f"{url}/@warpgate/api/ticket-requests",
                json={"target_name": target.name, "description": "temp access"},
            )
            assert resp.status_code == 201
            secret = resp.json()["secret"]
            assert secret is not None

            # List my tickets
            resp = session.get(f"{url}/@warpgate/api/my-tickets")
            assert resp.status_code == 200
            tickets = resp.json()
            my_ticket = [t for t in tickets if t["target"] == target.name]
            assert len(my_ticket) >= 1
            ticket_id = my_ticket[0]["id"]

            # Revoke it
            resp = session.delete(f"{url}/@warpgate/api/my-tickets/{ticket_id}")
            assert resp.status_code == 204

            # Ticket should no longer work
            verify_session = requests.Session()
            verify_session.verify = False
            resp = verify_session.get(
                f"{url}/some/path?warpgate-target={target.name}",
                headers={"Authorization": f"Warpgate {secret}"},
                allow_redirects=False,
            )
            assert resp.status_code // 100 != 2
        finally:
            _disable_self_service(url)

    def test_negative_duration_rejected(
        self,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        """Negative or zero duration should be rejected."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, target, role = self._setup_user_and_target(api, echo_server_port)
            api.update_parameters(_default_params(
                ticket_self_service_enabled=True,
                ticket_auto_approve_existing_access=True,
            ))

        try:
            session = self._login(url, user.username)

            # Negative duration
            resp = session.post(
                f"{url}/@warpgate/api/ticket-requests",
                json={
                    "target_name": target.name,
                    "description": "test",
                    "duration_seconds": -100,
                },
            )
            assert resp.status_code == 400

            # Zero duration
            resp = session.post(
                f"{url}/@warpgate/api/ticket-requests",
                json={
                    "target_name": target.name,
                    "description": "test",
                    "duration_seconds": 0,
                },
            )
            assert resp.status_code == 400

            # Too short duration
            resp = session.post(
                f"{url}/@warpgate/api/ticket-requests",
                json={
                    "target_name": target.name,
                    "description": "test",
                    "duration_seconds": 30,
                },
            )
            assert resp.status_code == 400
        finally:
            _disable_self_service(url)

    def test_negative_uses_rejected(
        self,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        """Negative or zero uses should be rejected."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, target, role = self._setup_user_and_target(api, echo_server_port)
            api.update_parameters(_default_params(
                ticket_self_service_enabled=True,
                ticket_auto_approve_existing_access=True,
            ))

        try:
            session = self._login(url, user.username)

            resp = session.post(
                f"{url}/@warpgate/api/ticket-requests",
                json={
                    "target_name": target.name,
                    "description": "test",
                    "uses": -1,
                },
            )
            assert resp.status_code == 400

            resp = session.post(
                f"{url}/@warpgate/api/ticket-requests",
                json={
                    "target_name": target.name,
                    "description": "test",
                    "uses": 0,
                },
            )
            assert resp.status_code == 400
        finally:
            _disable_self_service(url)
