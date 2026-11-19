import pytest
import requests

from .conftest import WarpgateProcess
from .util import post_declaring_length

ANONYMOUS_LIMIT = 64 * 1024
AUTHENTICATED_LIMIT = 8 * 1024 * 1024
LOGIN = "/@warpgate/api/auth/login"
ADMIN_TOKEN = {"X-Warpgate-Token": "token-value"}

JSON = "application/json"
FORM = "application/x-www-form-urlencoded"

# Every route that reads a request body before the caller is authenticated.
pre_auth_routes = pytest.mark.parametrize(
    "path,content_type",
    [
        pytest.param(LOGIN, JSON, id="login"),
        pytest.param("/@warpgate/api/auth/otp", JSON, id="otp"),
        pytest.param("/@warpgate/api/sso/return", FORM, id="sso-return"),
        pytest.param(
            "/@warpgate/api/sso/providers/none/backchannel-logout",
            FORM,
            id="backchannel-logout",
        ),
    ],
)


class TestHttpBodyLimit:
    @pre_auth_routes
    def test_declared_oversized_body_is_refused_unread(
        self, shared_wg: WarpgateProcess, path, content_type
    ):
        status, _ = post_declaring_length(
            shared_wg.http_port,
            path,
            ANONYMOUS_LIMIT + 1,
            headers={"Content-Type": content_type},
        )
        assert status == 413
        self._assert_alive(shared_wg)

    @pre_auth_routes
    def test_chunked_oversized_body_is_refused(
        self, shared_wg: WarpgateProcess, path, content_type
    ):
        # Exactly one byte over, so the server has read nearly everything when it
        # answers and closing on the unread rest cannot reset the response away.
        size = ANONYMOUS_LIMIT + 1
        chunks = (b"a" * min(4096, size - offset) for offset in range(0, size, 4096))
        response = requests.post(
            f"https://localhost:{shared_wg.http_port}{path}",
            data=chunks,
            headers={"Content-Type": content_type},
            verify=False,
        )
        assert response.status_code == 413
        self._assert_alive(shared_wg)

    def test_unknown_token_gets_the_anonymous_limit(self, shared_wg: WarpgateProcess):
        status, _ = post_declaring_length(
            shared_wg.http_port,
            LOGIN,
            ANONYMOUS_LIMIT + 1,
            headers={"X-Warpgate-Token": "not-the-token"},
        )
        assert status == 413

    def test_authenticated_limit(self, shared_wg: WarpgateProcess):
        # Not JSON, so it is refused for its content and changes nothing; what
        # matters is that it got as far as being parsed.
        response = requests.put(
            f"https://localhost:{shared_wg.http_port}/@warpgate/admin/api/parameters",
            data=b"a" * (ANONYMOUS_LIMIT + 1),
            headers={"Content-Type": "application/json", **ADMIN_TOKEN},
            verify=False,
        )
        assert response.status_code == 400

        status, _ = post_declaring_length(
            shared_wg.http_port, LOGIN, AUTHENTICATED_LIMIT + 1, headers=ADMIN_TOKEN
        )
        assert status == 413

    @staticmethod
    def _assert_alive(wg: WarpgateProcess):
        assert wg.process.poll() is None
        response = requests.get(
            f"https://localhost:{wg.http_port}/@warpgate/api/info", verify=False
        )
        assert response.status_code == 200
