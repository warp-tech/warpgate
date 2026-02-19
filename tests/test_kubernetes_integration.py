from datetime import datetime, timezone, timedelta
import shutil
import subprocess
import uuid

import aiohttp
import pytest

from .api_client import admin_client, sdk
from .conftest import WarpgateProcess


pytestmark = pytest.mark.usefixtures("report_generation")


@pytest.mark.skipif(shutil.which("kubectl") is None, reason="kubectl is not available")
class TestKubernetesIntegration:
    @pytest.mark.asyncio
    async def test_kubectl_through_warpgate(
        self, processes, shared_wg: WarpgateProcess
    ):
        k3s = processes.start_k3s()
        k3s_port = k3s["port"]
        k3s_token = k3s["token"]

        url = f"https://localhost:{shared_wg.http_port}"

        target_name = f"k8s-{uuid.uuid4()}"

        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid.uuid4()}"))
            user = api.create_user(
                sdk.CreateUserRequest(username=f"user-{uuid.uuid4()}")
            )
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id)
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=target_name,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetKubernetesOptions(
                            kind="Kubernetes",
                            auth=sdk.KubernetesTargetAuth(
                                sdk.KubernetesTargetAuthKubernetesTargetTokenAuth(
                                    token=k3s_token, kind="Token"
                                )
                            ),
                            cluster_url=f"https://127.0.0.1:{k3s_port}",
                            tls=sdk.Tls(
                                mode=sdk.TlsMode.PREFERRED,
                                verify=False,
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(target.id, role.id)

        # Login as user and create API token
        async with aiohttp.ClientSession() as session:
            headers = {"Host": f"localhost:{shared_wg.http_port}"}

            resp = await session.post(
                f"{url}/@warpgate/api/auth/login",
                json={
                    "username": user.username,
                    "password": "123",
                },
                headers=headers,
                ssl=False,
            )
            resp.raise_for_status()

            resp = await session.post(
                f"{url}/@warpgate/api/profile/api-tokens",
                json={
                    "label": "test-token",
                    "expiry": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
                },
                ssl=False,
            )
            resp.raise_for_status()
            user_token = (await resp.json())["secret"]

        server = f"https://127.0.0.1:{shared_wg.kubernetes_port}/{target_name}"
        cmd = [
            "kubectl",
            "get",
            "pods",
            "--server",
            server,
            "--insecure-skip-tls-verify",
            "--token",
            user_token,
            "-n",
            "default",
        ]

        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert p.returncode == 0, (
            f"kubectl failed: stdout={p.stdout!r} stderr={p.stderr!r}"
        )
