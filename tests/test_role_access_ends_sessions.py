"""Sessions end when the role assignment that admitted them is revoked or expires."""

import subprocess
from datetime import datetime, timedelta, timezone

import requests

from .conftest import ProcessManager, WarpgateProcess
from .test_ssh_proto import common_args, setup_user_and_target
from .util import wait_port

TOKEN = {"X-Warpgate-Token": "token-value"}


def _admin(wg: WarpgateProcess, method: str, path: str, body=None):
    r = requests.request(
        method,
        f"https://localhost:{wg.http_port}/@warpgate/admin/api{path}",
        headers=TOKEN,
        json=body,
        verify=False,
        timeout=10,
    )
    assert r.status_code < 300, (method, path, r.status_code, r.text[:200])
    return r.json() if r.text else None


def _role_ids(wg, user):
    return [r["id"] for r in _admin(wg, "GET", f"/users/{user.id}/roles")]


def _long_session(processes, wg, user, target):
    return processes.start_ssh_client(
        f"{user.username}:{target.name}@localhost",
        "-p",
        str(wg.ssh_port),
        *common_args,
        "sh",
        "-c",
        "'sleep 120'",
        password="123",
    )


def _ended_within(proc, seconds) -> bool:
    try:
        proc.wait(timeout=seconds)
        return True
    except subprocess.TimeoutExpired:
        return False


class Test:
    def test_revoking_the_role_ends_the_session(
        self, processes: ProcessManager, timeout, wg_c_ed25519_pubkey
    ):
        wg = processes.start_wg()
        wait_port(wg.ssh_port, for_process=wg.process)
        user, target = setup_user_and_target(processes, wg, wg_c_ed25519_pubkey)
        other, other_target = setup_user_and_target(processes, wg, wg_c_ed25519_pubkey)
        session = _long_session(processes, wg, user, target)
        bystander = _long_session(processes, wg, other, other_target)
        assert not _ended_within(session, 8), "the session did not start"
        assert bystander.poll() is None

        for role_id in _role_ids(wg, user):
            _admin(wg, "DELETE", f"/users/{user.id}/roles/{role_id}")

        assert _ended_within(session, 15), "the session outlived the revoked role"
        assert bystander.poll() is None, "an unrelated user's session was closed"
        bystander.kill()

    def test_an_expiring_role_ends_the_session(
        self, processes: ProcessManager, timeout, wg_c_ed25519_pubkey
    ):
        wg = processes.start_wg()
        wait_port(wg.ssh_port, for_process=wg.process)
        user, target = setup_user_and_target(processes, wg, wg_c_ed25519_pubkey)
        session = _long_session(processes, wg, user, target)
        assert not _ended_within(session, 8), "the session did not start"

        soon = (datetime.now(timezone.utc) + timedelta(seconds=8)).isoformat()
        for role_id in _role_ids(wg, user):
            _admin(wg, "PUT", f"/users/{user.id}/roles/{role_id}", {"expires_at": soon})

        assert not _ended_within(session, 4), "the session ended before the expiry"
        assert _ended_within(session, 20), "the session outlived the expired role"
