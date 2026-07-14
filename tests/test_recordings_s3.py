import subprocess
import time
from uuid import uuid4

import boto3
import pytest
import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .test_ssh_proto import common_args, setup_user_and_target
from .util import wait_port

MINIO_USER = "minioadmin"
MINIO_PASSWORD = "minioadmin"
BUCKET = "warpgate-recordings"


@pytest.fixture(scope="session")
def minio(processes: ProcessManager):
    port = processes.start_minio(MINIO_USER, MINIO_PASSWORD)
    wait_port(port, recv=False)
    endpoint = f"http://localhost:{port}"
    s3 = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=MINIO_USER,
        aws_secret_access_key=MINIO_PASSWORD,
        region_name="us-east-1",
    )
    # MinIO needs a moment after the port opens before it serves the S3 API.
    deadline = time.monotonic() + 30
    while True:
        try:
            s3.create_bucket(Bucket=BUCKET)
            break
        except Exception:
            if time.monotonic() > deadline:
                raise
            time.sleep(1)
    yield endpoint, s3


def _configure_s3(url, endpoint):
    with admin_client(url) as api:
        api.update_parameters(
            sdk.ParameterUpdate(
                recordings_enable=True,
                recordings_storage=sdk.RecordingsStorageConfig(
                    sdk.RecordingsStorageConfigS3StorageConfig(
                        kind="S3",
                        bucket=BUCKET,
                        region="us-east-1",
                        endpoint=endpoint,
                        path_style=True,
                        prefix="",
                        credentials=sdk.S3Credentials(
                            sdk.S3CredentialsStaticCredentials(
                                mode="Static",
                                access_key_id=MINIO_USER,
                                secret_access_key=MINIO_PASSWORD,
                            )
                        ),
                    )
                ),
            )
        )


def _find_completed_terminal_recording(api):
    for session in sorted(
        api.get_sessions().items, key=lambda s: s.started, reverse=True
    ):
        for rec in api.get_session_recordings(session.id):
            if rec.kind == sdk.RecordingKind.TERMINAL and rec.ended is not None:
                return rec
    return None


class Test:
    def test_s3_recording_roundtrip(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
        minio,
    ):
        endpoint, s3 = minio

        wg = processes.start_wg(config_patch={"recordings": {"enable": True}})
        wait_port(wg.http_port, recv=False)
        url = f"https://localhost:{wg.http_port}"

        _configure_s3(url, endpoint)

        user, ssh_target = setup_user_and_target(processes, wg, wg_c_ed25519_pubkey)

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

        # Wait for the recorder to finalise: on S3 the local scratch is only
        # dropped and the object completed once the session ends.
        recording = None
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            with admin_client(url) as api:
                recording = _find_completed_terminal_recording(api)
            if recording is not None:
                break
            time.sleep(0.5)
        assert recording is not None, "no completed terminal recording found"

        # The object must actually be in the bucket.
        listing = s3.list_objects_v2(Bucket=BUCKET)
        keys = [obj["Key"] for obj in listing.get("Contents", [])]
        assert any(k.endswith("data.ndjson") for k in keys), (
            f"no recording object in bucket: {keys}"
        )

        # The completed recording is served by downloading it back from S3
        # (the local scratch is gone), so a successful cast proves the round trip.
        resp = requests.get(
            f"{url}/@warpgate/admin/api/recordings/{recording.id}/cast",
            headers={"X-Warpgate-Token": "token-value"},
            verify=False,
        )
        assert resp.status_code == 200, f"cast fetch failed: {resp.status_code}"
        assert marker in resp.text, "recorded terminal output missing the marker"
