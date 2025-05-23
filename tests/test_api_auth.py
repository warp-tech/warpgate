import contextlib
from .api_client import sdk
from .conftest import WarpgateProcess
from .test_http_common import *  # noqa


@contextlib.contextmanager
def assert_401():
    with pytest.raises(sdk.ApiException) as e:
        yield
    assert e.value.status == 401


class TestAPIAuth:
    def test_unavailable_without_auth(
        self,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"

        config = sdk.Configuration(
            host=f"{url}/@warpgate/admin/api",
        )
        config.verify_ssl = False

        with sdk.ApiClient(config) as api_client:
            api = sdk.DefaultApi(api_client)
            with assert_401():
                api.get_parameters()
            with assert_401():
                api.get_role("1")
            with assert_401():
                api.get_roles()
            with assert_401():
                api.get_user("1")
            with assert_401():
                api.get_users()
            with assert_401():
                api.get_target("1")
            with assert_401():
                api.get_targets()
            with assert_401():
                api.get_session("1")
            with assert_401():
                api.get_sessions()
