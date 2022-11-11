from uuid import uuid4

from .api_client import api_admin_session, api_create_target
from .conftest import ProcessManager, WarpgateProcess


class Test:
    def test_success(
        self,
        processes: ProcessManager,
        echo_server_port,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with api_admin_session(url) as session:
            echo_target = api_create_target(
                url,
                session,
                {
                    "name": f"echo-{uuid4()}",
                    "options": {
                        "kind": "Http",
                        "url": f"http://localhost:{echo_server_port}",
                        "tls": {
                            "mode": "Disabled",
                            "verify": False,
                        },
                    },
                },
            )

        proc = processes.start_wg(
            share_with=shared_wg,
            args=["test-target", echo_target["name"]],
        ).process
        proc.wait(timeout=timeout)
        assert proc.returncode == 0

    def test_fail_no_connection(
        self, processes: ProcessManager, timeout, shared_wg: WarpgateProcess
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with api_admin_session(url) as session:
            echo_target = api_create_target(
                url,
                session,
                {
                    "name": f"echo-{uuid4()}",
                    "options": {
                        "kind": "Http",
                        "url": "http://localhostbaddomain",
                        "tls": {
                            "mode": "Disabled",
                            "verify": False,
                        },
                    },
                },
            )

        proc = processes.start_wg(
            share_with=shared_wg,
            args=["test-target", echo_target["name"]],
        ).process
        proc.wait(timeout=timeout)
        assert proc.returncode != 0
