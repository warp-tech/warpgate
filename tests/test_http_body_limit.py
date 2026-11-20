from uuid import uuid4

import pytest
import requests

from .api_client import admin_client, sdk
from .conftest import WarpgateProcess
from .util import post_declaring_length

BODY_LIMIT = 64 * 1024
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

# The routes that take more than BODY_LIMIT, with the limit each one applies
# itself once it has let the caller in.
GITOPS_LIMIT = 32 * 1024 * 1024
self_limited_routes = pytest.mark.parametrize(
    "method,path,limit",
    [
        pytest.param(
            "PUT", "/@warpgate/admin/api/parameters/logo", 5 * 1024 * 1024, id="logo"
        ),
        pytest.param(
            "POST", "/@warpgate/admin/api/gitops/sync", GITOPS_LIMIT, id="gitops-sync"
        ),
        pytest.param(
            "POST",
            "/@warpgate/admin/api/gitops/dry-run",
            GITOPS_LIMIT,
            id="gitops-dry-run",
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
            BODY_LIMIT + 1,
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
        size = BODY_LIMIT + 1
        chunks = (b"a" * min(4096, size - offset) for offset in range(0, size, 4096))
        response = requests.post(
            f"https://localhost:{shared_wg.http_port}{path}",
            data=chunks,
            headers={"Content-Type": content_type},
            verify=False,
        )
        assert response.status_code == 413
        self._assert_alive(shared_wg)

    def test_an_admin_gets_the_same_limit(self, shared_wg: WarpgateProcess):
        # Not JSON, so it is refused for its content and changes nothing; what
        # matters is that it got as far as being parsed.
        response = requests.put(
            f"https://localhost:{shared_wg.http_port}/@warpgate/admin/api/parameters",
            data=b"a" * BODY_LIMIT,
            headers={"Content-Type": "application/json", **ADMIN_TOKEN},
            verify=False,
        )
        assert response.status_code == 400

        status, _ = post_declaring_length(
            shared_wg.http_port,
            "/@warpgate/admin/api/parameters",
            BODY_LIMIT + 1,
            headers=ADMIN_TOKEN,
            method="PUT",
        )
        assert status == 413

    @self_limited_routes
    def test_self_limited_route_has_its_own_limit(
        self, shared_wg: WarpgateProcess, method, path, limit
    ):
        response = requests.request(
            method,
            f"https://localhost:{shared_wg.http_port}{path}",
            data=b"a" * (BODY_LIMIT + 1),
            headers={"Content-Type": "application/json", **ADMIN_TOKEN},
            verify=False,
        )
        assert response.status_code == 400

        status, _ = post_declaring_length(
            shared_wg.http_port, path, limit + 1, headers=ADMIN_TOKEN, method=method
        )
        assert status == 413

    @self_limited_routes
    def test_self_limited_route_reads_nothing_before_admitting_the_caller(
        self, shared_wg: WarpgateProcess, method, path, limit
    ):
        # A body limit applied first would answer 413 instead.
        status, _ = post_declaring_length(
            shared_wg.http_port, path, limit + 1, method=method
        )
        assert status == 401

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
        session = requests.Session()
        session.verify = False
        login = session.post(
            f"{url}{LOGIN}", json={"username": user.username, "password": "123"}
        )
        assert login.status_code // 100 == 2
        cookies = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
        status, body = post_declaring_length(
            shared_wg.http_port,
            path,
            limit + 1,
            headers={"Cookie": cookies},
            method=method,
        )
        assert (status, body) == (401, "authorization error")

    def test_gitops_files_over_the_common_limit(self, shared_wg: WarpgateProcess):
        padding = "#" + "x" * BODY_LIMIT
        with admin_client(f"https://localhost:{shared_wg.http_port}") as api:
            dry = api.dry_run_gitops(sdk.SyncGitopsRequest(yaml=f"{padding}\n{{}}"))
        # The complaint is about the document after the padding, so all of it
        # arrived.
        assert dry.source == "request"
        assert dry.error.startswith("request.yaml:2:1:")

    @staticmethod
    def _assert_alive(wg: WarpgateProcess):
        assert wg.process.poll() is None
        response = requests.get(
            f"https://localhost:{wg.http_port}/@warpgate/api/info", verify=False
        )
        assert response.status_code == 200
