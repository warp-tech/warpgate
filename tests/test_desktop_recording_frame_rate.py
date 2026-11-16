"""The `desktop_recording_frame_rate` parameter: default, update, bounds."""

import requests

from .conftest import WarpgateProcess

TOKEN = {"X-Warpgate-Token": "token-value"}


def _url(wg: WarpgateProcess) -> str:
    return f"https://localhost:{wg.http_port}/@warpgate/admin/api/parameters"


def _get(wg: WarpgateProcess) -> dict:
    r = requests.get(_url(wg), headers=TOKEN, verify=False, timeout=10)
    assert r.status_code == 200
    return r.json()


def _put(wg: WarpgateProcess, value) -> int:
    return requests.put(
        _url(wg),
        headers=TOKEN,
        json={"desktop_recording_frame_rate": value},
        verify=False,
        timeout=10,
    ).status_code


class Test:
    def test_frame_rate_defaults_to_30_and_can_be_lowered(self, shared_wg: WarpgateProcess):
        assert _get(shared_wg)["desktop_recording_frame_rate"] == 30
        try:
            assert _put(shared_wg, 5) // 100 == 2
            assert _get(shared_wg)["desktop_recording_frame_rate"] == 5
        finally:
            assert _put(shared_wg, 30) // 100 == 2

    def test_frame_rate_outside_1_to_30_is_refused(self, shared_wg: WarpgateProcess):
        for value in (0, -1, 31, 120):
            assert _put(shared_wg, value) == 400, value
        assert _get(shared_wg)["desktop_recording_frame_rate"] == 30
