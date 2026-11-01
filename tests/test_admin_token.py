import subprocess

from .conftest import ProcessManager
from .util import wait_port


def test_empty_admin_token_refuses_to_start(processes: ProcessManager, timeout):
    # An empty token would authorize requests with an empty X-Warpgate-Token.
    wg = processes.start_wg()
    wait_port(wg.http_port, for_process=wg.process, recv=False, timeout=timeout)

    node = processes.start_wg(share_with=wg, env={"WARPGATE_ADMIN_TOKEN": ""})
    try:
        returncode = node.process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        raise AssertionError("warpgate kept running with an empty admin token")
    assert returncode != 0
