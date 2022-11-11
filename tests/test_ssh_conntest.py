from pathlib import Path
import subprocess
from textwrap import dedent
from uuid import uuid4

from .api_client import (
    api_admin_session,
    api_create_target,
)

from .conftest import ProcessManager, WarpgateProcess
from .util import alloc_port, wait_port


class Test:
    def test_success(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with api_admin_session(url) as session:
            ssh_target = api_create_target(
                url,
                session,
                {
                    "name": f"ssh-{uuid4()}",
                    "options": {
                        "kind": "Ssh",
                        "host": "localhost",
                        "port": ssh_port,
                        "username": "root",
                        "auth": {"kind": "PublicKey"},
                    },
                },
            )

        wg = processes.start_wg(
            share_with=shared_wg,
            args=["test-target", ssh_target["name"]],
        )
        wg.process.wait(timeout=timeout)
        assert wg.process.returncode == 0

    def test_fail(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        ssh_port = alloc_port()

        url = f"https://localhost:{shared_wg.http_port}"
        with api_admin_session(url) as session:
            ssh_target = api_create_target(
                url,
                session,
                {
                    "name": f"ssh-{uuid4()}",
                    "options": {
                        "kind": "Ssh",
                        "host": "localhost",
                        "port": ssh_port,
                        "username": "root",
                        "auth": {"kind": "PublicKey"},
                    },
                },
            )
        wg = processes.start_wg(
            args=["test-target", ssh_target["name"]],
            share_with=shared_wg,
        )
        wg.process.wait(timeout=timeout)
        assert wg.process.returncode != 0
