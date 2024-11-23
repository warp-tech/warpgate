from pathlib import Path
from textwrap import dedent
from uuid import uuid4

from .api_client import admin_client, sdk

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
        with admin_client(url) as api:
            ssh_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            host="localhost",
                            port=ssh_port,
                            username="root",
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(
                                    kind="PublicKey"
                                )
                            ),
                        )
                    ),
                )
            )

        wg = processes.start_wg(
            share_with=shared_wg,
            args=["test-target", ssh_target.name],
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
        with admin_client(url) as api:
            ssh_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            host="localhost",
                            port=ssh_port,
                            username="root",
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(
                                    kind="PublicKey"
                                )
                            ),
                        )
                    ),
                )
            )
        wg = processes.start_wg(
            args=["test-target", ssh_target.name],
            share_with=shared_wg,
        )
        wg.process.wait(timeout=timeout)
        assert wg.process.returncode != 0
