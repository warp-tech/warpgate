from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .test_http_common import *  # noqa


class Test:
    def test_success(
        self,
        processes: ProcessManager,
        echo_server_port,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            echo_target = api.create_target(sdk.TargetDataRequest(
                name=f"echo-{uuid4()}",
                options=sdk.TargetOptions(sdk.TargetOptionsTargetHTTPOptions(
                    kind="Http",
                    url=f"http://localhost:{echo_server_port}",
                    tls=sdk.Tls(
                        mode=sdk.TlsMode.DISABLED,
                        verify=False,
                    ),
                )),
            ))

        proc = processes.start_wg(
            share_with=shared_wg,
            args=["test-target", echo_target.name],
        ).process
        proc.wait(timeout=timeout)
        assert proc.returncode == 0

    def test_fail_no_connection(
        self, processes: ProcessManager, timeout, shared_wg: WarpgateProcess
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            echo_target = api.create_target(sdk.TargetDataRequest(
                name=f"echo-{uuid4()}",
                options=sdk.TargetOptions(sdk.TargetOptionsTargetHTTPOptions(
                    kind="Http",
                    url="http://localhostbaddomain",
                    tls=sdk.Tls(
                        mode=sdk.TlsMode.DISABLED,
                        verify=False,
                    ),
                )),
            ))

        proc = processes.start_wg(
            share_with=shared_wg,
            args=["test-target", echo_target.name],
        ).process
        proc.wait(timeout=timeout)
        assert proc.returncode != 0
