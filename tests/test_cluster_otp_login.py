from base64 import b64decode
from contextlib import ExitStack
from uuid import uuid4

import pyotp
import pytest
import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .test_http_common import echo_server_port  # noqa: F401
from .util import proxy_protocol_relay, wait_port


@pytest.fixture
def load_balancer():
    with ExitStack() as relays:
        yield lambda port: relays.enter_context(proxy_protocol_relay(port))


class Test:
    @pytest.mark.parametrize("proxy_protocol", [False, True])
    def test_cross_node_otp_login(
        self,
        processes: ProcessManager,
        otp_key_base32,
        otp_key_base64,
        echo_server_port,
        load_balancer,
        proxy_protocol,
    ):
        # Two nodes on one database. The password step lands on node A, which
        # holds the in-memory auth state; the OTP step is deliberately sent to
        # node B. B holds no auth state, so it must resolve the owning node from
        # the shared sessions table (keyed by the browser session id) and
        # forward the OTP submission to A. Without that forwarding the login
        # thrashes and MFA is impossible behind a non-sticky load balancer.
        #
        # With `proxy_protocol`, clients reach both nodes through a relay that
        # sends a PROXY header, while B still connects to A directly.
        node_a = processes.start_wg(
            config_patch={"http": {"proxy_protocol": proxy_protocol}}
        )
        wait_port(node_a.http_port, recv=False)
        node_b = processes.start_wg(share_with=node_a)
        wait_port(node_b.http_port, recv=False)

        def front(node):
            port = node.http_port
            return f"https://localhost:{load_balancer(port) if proxy_protocol else port}"

        url_a = front(node_a)
        url_b = front(node_b)

        if proxy_protocol:
            with pytest.raises(requests.exceptions.ConnectionError):
                requests.get(
                    f"https://localhost:{node_a.http_port}/@warpgate/api/info",
                    verify=False,
                )

        with admin_client(url_a) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.create_otp_credential(
                user.id,
                sdk.NewOtpCredential(secret_key=list(b64decode(otp_key_base64))),
            )
            api.update_user(
                user.id,
                sdk.UserDataRequest(
                    username=user.username,
                    credential_policy=sdk.UserRequireCredentialsPolicy(
                        http=["Password", "Totp"]
                    ),
                ),
            )
            api.add_user_role(user.id, role.id)
            echo_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"echo-{uuid4()}",
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
            api.add_target_role(echo_target.id, role.id)

        session = requests.Session()
        session.verify = False

        totp = pyotp.TOTP(otp_key_base32)

        # Password step on node A: creates the auth state (and the sessions row
        # stamped with A's node id) and needs a second factor.
        response = session.post(
            f"{url_a}/@warpgate/api/auth/login",
            json={"username": user.username, "password": "123"},
        )
        assert response.status_code // 100 != 2

        # Repeating the password step on node B must reach A's auth state
        # instead of starting a second login on B.
        response = session.post(
            f"{url_b}/@warpgate/api/auth/login",
            json={"username": user.username, "password": "123"},
        )
        assert response.status_code // 100 != 2

        with admin_client(url_a) as api:
            sessions = api.get_sessions().items
            assert len(sessions) == 1
            if proxy_protocol:
                assert sessions[0].remote_address.startswith("203.0.113.10:")

        # OTP step on node B: forwarded to A, so it must succeed.
        response = session.post(
            f"{url_b}/@warpgate/api/auth/otp",
            json={"otp": totp.now()},
        )
        assert response.status_code // 100 == 2

        # The now-authenticated session works on node B end to end.
        response = session.get(
            f"{url_b}/some/path?warpgate-target={echo_target.name}",
            allow_redirects=False,
        )
        assert response.status_code // 100 == 2
        assert response.json()["path"] == "/some/path"
