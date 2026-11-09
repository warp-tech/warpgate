import base64
import os

import pytest
import requests

from .api_client import sdk, admin_client
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_mysql_port, wait_port

PNG = b"\x89PNG\r\n\x1a\n" + b"logo-bytes"

# The API caps the data URL at 4 MiB, i.e. about 3 MB of image.
MAX_DATA_URL_LENGTH = 4 * 1024 * 1024


def _data_url(content_type: str, data: bytes) -> str:
    return f"data:{content_type};base64,{base64.b64encode(data).decode()}"


def _session(wg: WarpgateProcess) -> requests.Session:
    session = requests.Session()
    session.verify = False
    session.headers["X-Warpgate-Token"] = "token-value"
    return session


def _url(wg: WarpgateProcess, path: str) -> str:
    return f"https://localhost:{wg.http_port}/@warpgate{path}"


def _set_logo(wg: WarpgateProcess, logo) -> requests.Response:
    # The SDK drops None fields, so an explicit null has to go out as raw JSON.
    return _session(wg).put(_url(wg, "/admin/api/parameters"), json={"logo": logo})


def _info_logo_etag(wg: WarpgateProcess):
    response = requests.get(_url(wg, "/api/info"), verify=False)
    response.raise_for_status()
    return response.json()["logo_etag"]


def _assert_round_trip(wg: WarpgateProcess, content_type: str, data: bytes) -> None:
    assert _set_logo(wg, _data_url(content_type, data)).status_code == 201
    etag = _info_logo_etag(wg)
    assert etag
    response = requests.get(_url(wg, f"/api/logo?v={etag}"), verify=False)
    assert response.status_code == 200
    assert response.headers["Content-Type"] == content_type
    assert response.content == data


@pytest.fixture
def clean_logo(shared_wg: WarpgateProcess):
    assert _set_logo(shared_wg, None).status_code == 201
    yield shared_wg
    assert _set_logo(shared_wg, None).status_code == 201


class TestLogo:
    def test_unset_logo_is_not_found(self, clean_logo: WarpgateProcess):
        wg = clean_logo
        assert _info_logo_etag(wg) is None
        assert requests.get(_url(wg, "/api/logo"), verify=False).status_code == 404

    def test_logo_cache_headers(self, clean_logo: WarpgateProcess):
        wg = clean_logo
        _assert_round_trip(wg, "image/png", PNG)
        etag = _info_logo_etag(wg)

        with admin_client(f"https://localhost:{wg.http_port}") as api:
            assert api.get_parameters().logo_etag == etag

        # Unauthenticated: the login page needs the logo too.
        response = requests.get(_url(wg, "/api/logo"), verify=False)
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-cache"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["Content-Security-Policy"] == "sandbox"

        versioned = requests.get(_url(wg, f"/api/logo?v={etag}"), verify=False)
        assert (
            versioned.headers["Cache-Control"] == "public, max-age=31536000, immutable"
        )

        stale = requests.get(_url(wg, "/api/logo?v=0000"), verify=False)
        assert stale.status_code == 200
        assert stale.headers["Cache-Control"] == "no-cache"

    def test_new_logo_gets_a_new_etag(self, clean_logo: WarpgateProcess):
        wg = clean_logo
        _assert_round_trip(wg, "image/png", PNG)
        first = _info_logo_etag(wg)
        svg = b'<svg xmlns="http://www.w3.org/2000/svg"/>'
        _assert_round_trip(wg, "image/svg+xml", svg)
        second = _info_logo_etag(wg)
        assert first != second

        # The old content-addressed URL must not be cached as immutable anymore.
        old = requests.get(_url(wg, f"/api/logo?v={first}"), verify=False)
        assert old.headers["Cache-Control"] == "no-cache"
        assert old.content == svg

    def test_unrelated_update_keeps_the_logo(self, clean_logo: WarpgateProcess):
        wg = clean_logo
        _assert_round_trip(wg, "image/png", PNG)
        etag = _info_logo_etag(wg)
        with admin_client(f"https://localhost:{wg.http_port}") as api:
            api.update_parameters(sdk.ParameterUpdate(banner=""))
        assert _info_logo_etag(wg) == etag

    def test_clearing_the_logo(self, clean_logo: WarpgateProcess):
        wg = clean_logo
        _assert_round_trip(wg, "image/png", PNG)
        assert _set_logo(wg, None).status_code == 201
        assert _info_logo_etag(wg) is None
        assert requests.get(_url(wg, "/api/logo"), verify=False).status_code == 404

    @pytest.mark.parametrize(
        "logo",
        ["data:image/png;base64,iVBORw0KGgo", "data:image/png;base64,iVBORw0KGgp="],
        ids=["unpadded", "trailing-bits"],
    )
    def test_accepts_base64_browsers_accept(self, clean_logo: WarpgateProcess, logo):
        assert _set_logo(clean_logo, logo).status_code == 201
        etag = _info_logo_etag(clean_logo)
        response = requests.get(_url(clean_logo, f"/api/logo?v={etag}"), verify=False)
        assert response.content == b"\x89PNG\r\n\x1a\n"

    @pytest.mark.parametrize(
        "logo",
        [
            "",
            "https://example.com/logo.png",
            _data_url("text/html", b"<script></script>"),
            "data:image/png;base64,not base64!",
            # Passes the schema pattern, but no base64 decoder accepts it.
            "data:image/png;base64,iVBORw0KGgoAB",
            "data:image/png," + "x",
        ],
    )
    def test_rejects_anything_but_image_data_urls(
        self, clean_logo: WarpgateProcess, logo
    ):
        assert _set_logo(clean_logo, logo).status_code == 400
        assert _info_logo_etag(clean_logo) is None

    def test_size_cap(self, clean_logo: WarpgateProcess):
        prefix_length = len(_data_url("image/png", b""))
        # Largest payload whose base64 still fits the cap, and one 3-byte group over.
        fits = (MAX_DATA_URL_LENGTH - prefix_length) // 4 * 3
        assert len(_data_url("image/png", os.urandom(fits))) <= MAX_DATA_URL_LENGTH
        over_cap = _data_url("image/png", os.urandom(fits + 3))
        assert _set_logo(clean_logo, over_cap).status_code == 400
        _assert_round_trip(clean_logo, "image/png", os.urandom(fits))


def _start_postgres(processes: ProcessManager) -> str:
    port = processes.start_postgres_server()
    return f"postgres://user:123@localhost:{port}/db"


def _start_mysql(processes: ProcessManager) -> str:
    port = processes.start_mysql_server()
    wait_mysql_port(port)
    return f"mysql://root:123@localhost:{port}/db"


def _start_mariadb(processes: ProcessManager) -> str:
    port = processes.start_mariadb_server()
    wait_mysql_port(port)
    return f"mysql://root:123@localhost:{port}/db"


class TestLogoDatabaseBackends:
    """A near-cap logo must survive storage on every supported database, not
    just SQLite (MySQL's plain TEXT, for one, stops at 64 KB)."""

    @pytest.mark.parametrize(
        "start_db",
        [_start_postgres, _start_mysql, _start_mariadb],
        ids=["postgres", "mysql", "mariadb"],
    )
    def test_large_logo_round_trip(self, processes: ProcessManager, timeout, start_db):
        wg = processes.start_wg(database_url=start_db(processes))
        wait_port(wg.http_port, for_process=wg.process, recv=False, timeout=timeout)
        _assert_round_trip(wg, "image/png", os.urandom(3_000_000))


class TestLogoCluster:
    def test_any_node_serves_the_same_logo(self, processes: ProcessManager, timeout):
        node_a = processes.start_wg()
        wait_port(
            node_a.http_port, for_process=node_a.process, recv=False, timeout=timeout
        )
        node_b = processes.start_wg(share_with=node_a)
        wait_port(
            node_b.http_port, for_process=node_b.process, recv=False, timeout=timeout
        )

        _assert_round_trip(node_a, "image/png", PNG)
        etag = _info_logo_etag(node_a)
        # The URL a browser built from node A's info must stay valid on node B.
        assert _info_logo_etag(node_b) == etag
        response = requests.get(_url(node_b, f"/api/logo?v={etag}"), verify=False)
        assert response.content == PNG
        assert (
            response.headers["Cache-Control"] == "public, max-age=31536000, immutable"
        )
