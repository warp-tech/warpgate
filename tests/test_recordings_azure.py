"""End-to-end tests for the Azure Blob recordings backend.

These need a real storage account. Azurite cannot stand in: azure_storage_blob
1.x authenticates with Entra ID only, and refuses a non-HTTPS endpoint as soon
as a credential is present, so the emulator cannot serve any of the credential
modes Warpgate offers.

Set the environment below to run them; without it the whole module is skipped,
which is what CI does.

    WARPGATE_AZURE_TEST_ACCOUNT     storage account name
    WARPGATE_AZURE_TEST_CONTAINER   container name (must already exist)

    # for the ServicePrincipal mode
    WARPGATE_AZURE_TEST_TENANT_ID
    WARPGATE_AZURE_TEST_CLIENT_ID
    WARPGATE_AZURE_TEST_CLIENT_SECRET

`tests/azure-e2e.sh` provisions all of this against a temporary resource group
and removes it afterwards.
"""

import base64
import json
import os
import time
from uuid import uuid4

import pytest
import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .test_ssh_proto import common_args, setup_user_and_target
from .util import wait_port

ACCOUNT = os.environ.get("WARPGATE_AZURE_TEST_ACCOUNT")
CONTAINER = os.environ.get("WARPGATE_AZURE_TEST_CONTAINER")
TENANT_ID = os.environ.get("WARPGATE_AZURE_TEST_TENANT_ID")
CLIENT_ID = os.environ.get("WARPGATE_AZURE_TEST_CLIENT_ID")
CLIENT_SECRET = os.environ.get("WARPGATE_AZURE_TEST_CLIENT_SECRET")

pytestmark = pytest.mark.skipif(
    not (ACCOUNT and CONTAINER),
    reason="needs a real Azure storage account; see the module docstring",
)

TOKEN_HEADER = {"X-Warpgate-Token": "token-value"}


def _credentials(mode):
    """The credential block for a mode, or None when it is not testable here.

    ManagedIdentity and WorkloadIdentity are deliberately absent: the first
    needs IMDS and the second a projected federated token, so neither resolves
    anywhere except inside Azure. They are covered by deploying, not by tests.
    """
    if mode == "ServicePrincipal":
        if not (TENANT_ID and CLIENT_ID and CLIENT_SECRET):
            return None
        return {
            "mode": "ServicePrincipal",
            "tenant_id": TENANT_ID,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        }
    if mode == "DeveloperTools":
        # Relies on an `az login` in the environment running the tests.
        return {"mode": "DeveloperTools"}
    raise AssertionError(f"unsupported mode {mode}")


def _storage_config(mode, prefix, serve_through_warpgate=True):
    return {
        "kind": "Azure",
        "account": ACCOUNT,
        "container": CONTAINER,
        "prefix": prefix,
        "serve_through_warpgate": serve_through_warpgate,
        "credentials": _credentials(mode),
    }


def _configure(url, config):
    response = requests.put(
        f"{url}/@warpgate/admin/api/parameters",
        headers=TOKEN_HEADER,
        json={"recordings_enable": True, "recordings_storage": config},
        verify=False,
    )
    response.raise_for_status()


def _test_connection(url, config):
    response = requests.post(
        f"{url}/@warpgate/admin/api/parameters/recordings-storage/test",
        headers=TOKEN_HEADER,
        json=config,
        verify=False,
    )
    response.raise_for_status()
    return response.json()


def _terminal_output(body):
    """The terminal bytes carried by a recording's ndjson.

    Each line is an item and the screen data is base64 inside it, so a marker
    never appears literally in the response body.
    """
    output = b""
    for line in body.splitlines():
        if not line:
            continue
        item = json.loads(line)
        if "data" in item:
            output += base64.b64decode(item["data"])
    return output


def _find_completed_terminal_recording(api):
    for session in sorted(
        api.get_sessions().items, key=lambda s: s.started, reverse=True
    ):
        for rec in api.get_session_recordings(session.id):
            if rec.kind == sdk.RecordingKind.TERMINAL and rec.ended is not None:
                return rec
    return None


def _record_a_session(processes, wg, pubkey, timeout):
    """Drive one SSH session through Warpgate and return its recording."""
    user, ssh_target = setup_user_and_target(processes, wg, pubkey)
    marker = f"hello-{uuid4().hex}"
    ssh_client = processes.start_ssh_client(
        f"{user.username}:{ssh_target.name}@localhost",
        "-p",
        str(wg.ssh_port),
        "-tt",
        *common_args,
        "echo",
        marker,
        password="123",
    )
    output = ssh_client.communicate(timeout=timeout)[0]
    assert marker.encode() in output

    url = f"https://localhost:{wg.http_port}"
    # The upload only completes when the session ends and the block list is
    # committed, so the recording is not readable the instant the shell exits.
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        with admin_client(url) as api:
            recording = _find_completed_terminal_recording(api)
        if recording is not None:
            return recording, marker
        time.sleep(0.5)
    raise AssertionError("no completed terminal recording appeared")


@pytest.mark.parametrize("mode", ["ServicePrincipal", "DeveloperTools"])
class TestAzureCredentialModes:
    """Each credential mode, across the operations the backend exposes."""

    def test_connection_test_succeeds(self, processes: ProcessManager, mode):
        if _credentials(mode) is None:
            pytest.skip(f"{mode} is not configured in the environment")

        wg = processes.start_wg()
        wait_port(wg.http_port, recv=False)
        url = f"https://localhost:{wg.http_port}"

        result = _test_connection(url, _storage_config(mode, "connection-test"))
        assert result["success"], result.get("error")

    def test_recording_round_trip_streamed(
        self, processes: ProcessManager, timeout, wg_c_ed25519_pubkey, mode
    ):
        """Record, then read it back through Warpgate rather than by redirect."""
        if _credentials(mode) is None:
            pytest.skip(f"{mode} is not configured in the environment")

        prefix = f"streamed-{uuid4().hex[:8]}"
        wg = processes.start_wg(config_patch={"recordings": {"enable": True}})
        wait_port(wg.http_port, recv=False)
        url = f"https://localhost:{wg.http_port}"
        _configure(url, _storage_config(mode, prefix, serve_through_warpgate=True))

        recording, marker = _record_a_session(
            processes, wg, wg_c_ed25519_pubkey, timeout
        )

        response = requests.get(
            f"{url}/@warpgate/admin/api/recordings/{recording.id}/data",
            headers=TOKEN_HEADER,
            verify=False,
        )
        assert response.status_code == 200
        # Served by Warpgate, so nothing should have pointed at the account.
        assert not response.history, "expected no redirect when streaming"
        assert marker.encode() in _terminal_output(response.text)

    def test_ranged_read_serves_partial_content(
        self, processes: ProcessManager, timeout, wg_c_ed25519_pubkey, mode
    ):
        """The players seek with `Range: bytes=N-`, so 206 and 416 have to work."""
        if _credentials(mode) is None:
            pytest.skip(f"{mode} is not configured in the environment")

        prefix = f"ranged-{uuid4().hex[:8]}"
        wg = processes.start_wg(config_patch={"recordings": {"enable": True}})
        wait_port(wg.http_port, recv=False)
        url = f"https://localhost:{wg.http_port}"
        _configure(url, _storage_config(mode, prefix, serve_through_warpgate=True))

        recording, _ = _record_a_session(processes, wg, wg_c_ed25519_pubkey, timeout)
        data_url = f"{url}/@warpgate/admin/api/recordings/{recording.id}/data"

        whole = requests.get(data_url, headers=TOKEN_HEADER, verify=False)
        assert whole.status_code == 200
        total = len(whole.content)
        assert total > 0

        offset = total // 2
        partial = requests.get(
            data_url,
            headers={**TOKEN_HEADER, "Range": f"bytes={offset}-"},
            verify=False,
        )
        assert partial.status_code == 206
        assert partial.content == whole.content[offset:]
        assert partial.headers["Content-Range"] == f"bytes {offset}-{total - 1}/{total}"

        # Starting at the end is unsatisfiable, and the player relies on the 416
        # to know it has reached the end of the recording.
        past_end = requests.get(
            data_url,
            headers={**TOKEN_HEADER, "Range": f"bytes={total}-"},
            verify=False,
        )
        assert past_end.status_code == 416

    def test_recording_round_trip_via_sas_redirect(
        self, processes: ProcessManager, timeout, wg_c_ed25519_pubkey, mode
    ):
        """With streaming off, playback redirects to a user-delegation SAS URL."""
        if _credentials(mode) is None:
            pytest.skip(f"{mode} is not configured in the environment")

        prefix = f"sas-{uuid4().hex[:8]}"
        wg = processes.start_wg(config_patch={"recordings": {"enable": True}})
        wait_port(wg.http_port, recv=False)
        url = f"https://localhost:{wg.http_port}"
        _configure(url, _storage_config(mode, prefix, serve_through_warpgate=False))

        recording, marker = _record_a_session(
            processes, wg, wg_c_ed25519_pubkey, timeout
        )

        response = requests.get(
            f"{url}/@warpgate/admin/api/recordings/{recording.id}/data",
            headers=TOKEN_HEADER,
            verify=False,
        )
        assert response.status_code == 200
        # requests follows the redirect, so a hop through the storage account is
        # what proves the SAS was minted and accepted.
        assert response.history, "expected a redirect to the storage account"
        assert ACCOUNT in response.history[0].headers["Location"]
        assert marker.encode() in _terminal_output(response.text)


class TestAzureSecretHandling:
    """The admin API must not hand the service principal's secret back."""

    def test_client_secret_is_never_returned(self, processes: ProcessManager):
        if _credentials("ServicePrincipal") is None:
            pytest.skip("ServicePrincipal is not configured in the environment")

        wg = processes.start_wg()
        wait_port(wg.http_port, recv=False)
        url = f"https://localhost:{wg.http_port}"
        _configure(url, _storage_config("ServicePrincipal", "secret-check"))

        response = requests.get(
            f"{url}/@warpgate/admin/api/parameters", headers=TOKEN_HEADER, verify=False
        )
        response.raise_for_status()
        stored = response.json()["recordings_storage"]
        assert stored["credentials"]["client_secret"] == ""
        assert CLIENT_SECRET not in response.text

    def test_a_blank_secret_keeps_the_stored_one(self, processes: ProcessManager):
        """Saving an untouched form must not wipe the credential."""
        if _credentials("ServicePrincipal") is None:
            pytest.skip("ServicePrincipal is not configured in the environment")

        wg = processes.start_wg()
        wait_port(wg.http_port, recv=False)
        url = f"https://localhost:{wg.http_port}"
        config = _storage_config("ServicePrincipal", "blank-secret-check")
        _configure(url, config)

        redacted = requests.get(
            f"{url}/@warpgate/admin/api/parameters", headers=TOKEN_HEADER, verify=False
        ).json()["recordings_storage"]
        assert redacted["credentials"]["client_secret"] == ""

        # Post the redacted form straight back, the way the UI would.
        _configure(url, redacted)

        # If the secret had been lost, the backend could no longer authenticate.
        result = _test_connection(url, redacted)
        assert result["success"], result.get("error")
