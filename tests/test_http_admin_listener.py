"""`http.admin`: the admin UI and API on a separate listener.

With it set, the main listener stops serving the admin UI and API (under both
`/@warpgate` and `/_warpgate`) except to cluster peers, which forward admin
calls to each other's main HTTP port.
"""

import re
import time

import aiohttp
import pytest
import requests
import yaml

from .api_client import admin_client
from .conftest import ProcessManager, WarpgateProcess, alloc_port
from .util import wait_port

TOKEN = {"X-Warpgate-Token": "token-value"}


def _get(port: int, path: str, headers=None) -> int:
    return requests.get(
        f"https://localhost:{port}{path}",
        headers=headers or {},
        verify=False,
        allow_redirects=False,
        timeout=10,
    ).status_code


def _admin_patch(port: int) -> dict:
    return {"http": {"admin": {"listen": f"0.0.0.0:{port}"}}}


def _start(processes: ProcessManager, admin_port: int, share_with=None) -> WarpgateProcess:
    wg = processes.start_wg(config_patch=_admin_patch(admin_port), share_with=share_with)
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    wait_port(admin_port, for_process=wg.process, recv=False)
    return wg


def _wait(predicate, timeout=20, what="condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.5)
    raise AssertionError(f"timed out waiting for {what}")


class Test:
    def test_admin_is_served_on_the_admin_listener_only(self, processes: ProcessManager, timeout):
        admin_port = alloc_port()
        wg = _start(processes, admin_port)

        for prefix in ("/@warpgate", "/_warpgate"):
            assert _get(wg.http_port, f"{prefix}/admin/api/users", TOKEN) == 404
            assert _get(wg.http_port, f"{prefix}/admin/api/users") == 404
            assert _get(wg.http_port, f"{prefix}/admin") == 404
            assert _get(wg.http_port, f"{prefix}/admin/api/openapi.json") == 404
            assert _get(admin_port, f"{prefix}/admin/api/users", TOKEN) == 200
            assert _get(admin_port, f"{prefix}/admin/api/users") == 401
            assert _get(admin_port, f"{prefix}/admin") == 200

        # Encoded, doubled and case variants never reach the admin API on the main listener.
        for path in (
            "/%40warpgate/admin/api/users",
            "/@warpgate/%61dmin/api/users",
            "/@warpgate//admin/api/users",
            "/@WARPGATE/admin/api/users",
            "/@warpgate/Admin/api/users",
        ):
            assert _get(wg.http_port, path, TOKEN) != 200, path

        # The user-facing side of the main listener is unchanged.
        assert _get(wg.http_port, "/@warpgate/api/info") == 200
        assert _get(wg.http_port, "/@warpgate") == 200

    @pytest.mark.asyncio
    async def test_admin_websockets_follow_the_listener(self, processes: ProcessManager, timeout):
        admin_port = alloc_port()
        wg = _start(processes, admin_port)
        path = "/@warpgate/admin/api/sessions/changes"
        async with aiohttp.ClientSession() as session:
            with pytest.raises(aiohttp.WSServerHandshakeError) as refused:
                await session.ws_connect(f"wss://localhost:{wg.http_port}{path}", headers=TOKEN, ssl=False)
            assert refused.value.status == 404
            ws = await session.ws_connect(f"wss://localhost:{admin_port}{path}", headers=TOKEN, ssl=False)
            await ws.close()

    def test_password_login_on_the_admin_listener(self, processes: ProcessManager, timeout):
        admin_port = alloc_port()
        _start(processes, admin_port)
        session = requests.Session()
        session.verify = False
        url = f"https://localhost:{admin_port}"
        r = session.post(f"{url}/@warpgate/api/auth/login", json={"username": "admin", "password": "123"})
        assert r.status_code // 100 == 2
        assert session.get(f"{url}/@warpgate/admin/api/users").status_code == 200

    def test_admin_listener_counts_the_port_in_the_origin_check(self, processes: ProcessManager, timeout):
        # Without Sec-Fetch headers the Origin decides; on the admin listener a page
        # on the main port of the same host is another origin.
        admin_port = alloc_port()
        wg = _start(processes, admin_port)
        session = requests.Session()
        session.verify = False
        admin = f"https://localhost:{admin_port}"
        r = session.post(f"{admin}/@warpgate/api/auth/login", json={"username": "admin", "password": "123"})
        assert r.status_code // 100 == 2

        def create_role(origin: str) -> int:
            return session.post(
                f"{admin}/@warpgate/admin/api/roles",
                json={"name": f"role-{alloc_port()}"},
                headers={"Origin": origin},
            ).status_code

        assert create_role(f"https://localhost:{wg.http_port}") == 401
        assert create_role(admin) // 100 == 2

    def test_info_tells_admins_where_the_admin_ui_is(self, processes: ProcessManager, timeout):
        admin_port = alloc_port()
        wg = _start(processes, admin_port)
        for port, expect_url in ((wg.http_port, True), (admin_port, False)):
            session = requests.Session()
            session.verify = False
            url = f"https://localhost:{port}"
            r = session.post(f"{url}/@warpgate/api/auth/login", json={"username": "admin", "password": "123"})
            assert r.status_code // 100 == 2
            info = session.get(f"{url}/@warpgate/api/info").json()
            if expect_url:
                assert info["admin_url"].endswith(f":{admin_port}/@warpgate/admin"), info["admin_url"]
            else:
                assert info.get("admin_url") is None
        # Anonymous visitors learn nothing about the admin listener.
        anon = requests.get(f"https://localhost:{wg.http_port}/@warpgate/api/info", verify=False).json()
        assert anon.get("admin_url") is None

    def test_without_admin_nothing_changes(self, shared_wg: WarpgateProcess):
        assert _get(shared_wg.http_port, "/@warpgate/admin/api/users", TOKEN) == 200
        assert _get(shared_wg.http_port, "/_warpgate/admin/api/users", TOKEN) == 200
        assert _get(shared_wg.http_port, "/@warpgate/admin") == 200

    def test_admin_can_be_turned_on_and_off_at_runtime(self, processes: ProcessManager, timeout):
        wg = processes.start_wg()
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        assert _get(wg.http_port, "/@warpgate/admin/api/users", TOKEN) == 200

        admin_port = alloc_port()
        config = yaml.safe_load(wg.config_path.open())
        config.setdefault("http", {})["admin"] = {"listen": f"0.0.0.0:{admin_port}"}
        wg.config_path.write_text(yaml.safe_dump(config))
        wait_port(admin_port, for_process=wg.process, recv=False)
        _wait(lambda: _get(wg.http_port, "/@warpgate/admin/api/users", TOKEN) == 404, what="main to stop serving admin")
        assert _get(admin_port, "/@warpgate/admin/api/users", TOKEN) == 200

        del config["http"]["admin"]
        wg.config_path.write_text(yaml.safe_dump(config))
        _wait(lambda: _get(wg.http_port, "/@warpgate/admin/api/users", TOKEN) == 200, what="main to serve admin again")

    def test_overlapping_admin_listener_refuses_to_start(self, processes: ProcessManager, timeout):
        # `[::]` covers IPv4 too, so this overlaps the main 0.0.0.0 listener on the same port.
        port = alloc_port()
        wg = processes.start_wg(http_port=port, config_patch={"http": {"admin": {"listen": f"[::]:{port}"}}})
        assert wg.process.wait(timeout=30) != 0
        assert "overlaps `http.listen`" in wg.log_path.read_text(errors="replace")

    def test_cluster_peers_still_reach_each_other(self, processes: ProcessManager, timeout):
        # Close-all fans out to every peer's main HTTP port under
        # /@warpgate/admin/api/cluster/close-sessions; the peer must serve it (2xx), not 404.
        admin_a, admin_b = alloc_port(), alloc_port()
        node_a = _start(processes, admin_a)
        node_b = _start(processes, admin_b, share_with=node_a)

        with admin_client(f"https://localhost:{admin_b}") as api:
            api.close_all_sessions()

        served = re.compile(r"cluster/close-sessions.*status=2\d\d")
        blocked = re.compile(r"cluster/close-sessions.*status=4\d\d")
        _wait(
            lambda: served.search(node_a.log_path.read_text(errors="replace")) is not None
            or blocked.search(node_a.log_path.read_text(errors="replace")) is not None,
            what="node A to log the cluster close-sessions call",
        )
        log_a = node_a.log_path.read_text(errors="replace")
        assert served.search(log_a), "node A did not serve the peer's close-sessions call"
        assert not blocked.search(log_a), "node A refused the peer's close-sessions call"
