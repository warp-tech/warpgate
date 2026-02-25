from datetime import datetime, timezone, timedelta
import shutil
import uuid
import subprocess

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import aiohttp
import pytest

from .api_client import admin_client, sdk
from .conftest import WarpgateProcess, K3sInstance


def run_kubectl(args):
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


pytestmark = pytest.mark.usefixtures("report_generation")


@pytest.mark.skipif(shutil.which("kubectl") is None, reason="kubectl is not available")
class TestKubernetesIntegration:
    @pytest.mark.asyncio
    async def test_kubectl_through_warpgate(
        self, processes, shared_wg: WarpgateProcess
    ):
        # start k3s and obtain a service-account token
        k3s: K3sInstance = processes.start_k3s()
        k3s_port = k3s.port
        k3s_token = k3s.token

        url = f"https://localhost:{shared_wg.http_port}"

        # create user/role and give them a password
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid.uuid4()}"))
            user = api.create_user(
                sdk.CreateUserRequest(username=f"user-{uuid.uuid4()}")
            )
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id)

        # generate a keypair for certificate auth using cryptography (avoid
        # depending on openssl binary in the container)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        pub_pem = (
            key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        # write the private key so that other helpers (if any) could inspect it
        key_path = processes.ctx.tmpdir / f"k8s-key-{uuid.uuid4()}.pem"
        key_path.write_text(key_pem)

        # issue certificate credential for the user
        with admin_client(url) as api:
            issued = api.issue_certificate_credential(
                user.id,
                sdk.IssueCertificateCredentialRequest(
                    label="kubectl-cert",
                    public_key_pem=pub_pem,
                ),
            )
        cert_pem = issued.certificate_pem

        # create a single token-based Kubernetes target (Warpgate→k8s auth)
        token_target_name = f"k8s-token-{uuid.uuid4()}"
        with admin_client(url) as api:
            token_target = api.create_target(
                sdk.TargetDataRequest(
                    name=token_target_name,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetKubernetesOptions(
                            kind="Kubernetes",
                            cluster_url=f"https://127.0.0.1:{k3s_port}",
                            namespace="default",
                            tls=sdk.Tls(mode=sdk.TlsMode.PREFERRED, verify=False),
                            auth=sdk.KubernetesTargetAuth(
                                sdk.KubernetesTargetAuthKubernetesTargetTokenAuth(
                                    kind="Token", token=k3s_token
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(token_target.id, role.id)

        # login and obtain a user API token
        async with aiohttp.ClientSession() as session:
            headers = {"Host": f"localhost:{shared_wg.http_port}"}
            resp = await session.post(
                f"{url}/@warpgate/api/auth/login",
                json={"username": user.username, "password": "123"},
                headers=headers,
                ssl=False,
            )
            resp.raise_for_status()
            resp = await session.post(
                f"{url}/@warpgate/api/profile/api-tokens",
                json={
                    "label": "test-token",
                    "expiry": (
                        datetime.now(timezone.utc) + timedelta(days=1)
                    ).isoformat(),
                },
                ssl=False,
            )
            resp.raise_for_status()
            user_token = (await resp.json())["secret"]

        # positive token auth (cluster side uses token always)
        server = f"https://127.0.0.1:{shared_wg.kubernetes_port}/{token_target_name}"
        token_cmd = [
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
        p = run_kubectl(token_cmd)
        assert p.returncode == 0, f"token positive failed: {p.stderr!r}"

        # negative token case
        bad_cmd = token_cmd.copy()
        bad_cmd[bad_cmd.index(user_token)] = user_token + "x"
        p = run_kubectl(bad_cmd)
        assert p.returncode != 0, "token target accepted invalid token"

        # positive client-certificate auth to Warpgate (user→wg)
        cert_file = processes.ctx.tmpdir / f"k8s-cert-{uuid.uuid4()}.pem"
        key_file = processes.ctx.tmpdir / f"k8s-key-{uuid.uuid4()}.pem"
        cert_file.write_text(cert_pem)
        key_file.write_text(key_path.read_text())
        # minimal kubeconfig again to avoid side-effects
        kubeconf = processes.ctx.tmpdir / f"kubeconfig-{uuid.uuid4()}.yaml"
        kubeconf.write_text("apiVersion: v1\nkind: Config\n")
        cert_cmd = [
            "kubectl",
            "--kubeconfig",
            str(kubeconf),
            "get",
            "pods",
            "--server",
            server,
            "--insecure-skip-tls-verify",
            "--client-certificate",
            str(cert_file),
            "--client-key",
            str(key_file),
            "-n",
            "default",
        ]
        p = run_kubectl(cert_cmd)
        assert p.returncode == 0, f"cert-to-wg positive failed: {p.stderr!r}"

        # negative cert to Warpgate (wrong key)
        wrong_key = processes.ctx.tmpdir / f"k8s-wrong-{uuid.uuid4()}.pem"
        # generate an unrelated key locally with cryptography
        wrong_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrong_pem = wrong_rsa.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        wrong_key.write_text(wrong_pem)
        bad_cert_cmd = cert_cmd.copy()
        bad_cert_cmd[bad_cert_cmd.index(str(key_file))] = str(wrong_key)
        p = run_kubectl(bad_cert_cmd)
        assert p.returncode != 0, "warpgate accepted invalid client cert"

    @pytest.mark.asyncio
    async def test_mtls_upstream_and_token_user(
        self, processes, shared_wg: WarpgateProcess
    ):
        # k3s already running above? start another instance for isolation
        k3s: K3sInstance = processes.start_k3s()
        k3s_port = k3s.port
        # client cert/key for warpgate->k8s
        mtls_cert = k3s.client_cert
        mtls_key = k3s.client_key
        # sanity‑check the values we got from start_k3s -- they must look like PEM
        assert mtls_cert and "BEGIN CERTIFICATE" in mtls_cert, "upstream cert missing or invalid"
        assert mtls_key and "BEGIN" in mtls_key, "upstream key missing or invalid"

        url = f"https://localhost:{shared_wg.http_port}"

        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid.uuid4()}"))
            user = api.create_user(
                sdk.CreateUserRequest(username=f"user-{uuid.uuid4()}")
            )
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id)

        # create certificate-auth target (Warpgate->k8s)
        token_target_name = f"k8s-mtls-{uuid.uuid4()}"
        with admin_client(url) as api:
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=token_target_name,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetKubernetesOptions(
                            kind="Kubernetes",
                            cluster_url=f"https://127.0.0.1:{k3s_port}",
                            namespace="default",
                            tls=sdk.Tls(mode=sdk.TlsMode.PREFERRED, verify=False),
                            auth=sdk.KubernetesTargetAuth(
                                sdk.KubernetesTargetAuthKubernetesTargetCertificateAuth(
                                    kind="Certificate",
                                    certificate=mtls_cert,
                                    private_key=mtls_key,
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(target.id, role.id)

        # login user and create token
        async with aiohttp.ClientSession() as session:
            headers = {"Host": f"localhost:{shared_wg.http_port}"}
            resp = await session.post(
                f"{url}/@warpgate/api/auth/login",
                json={"username": user.username, "password": "123"},
                headers=headers,
                ssl=False,
            )
            resp.raise_for_status()
            resp = await session.post(
                f"{url}/@warpgate/api/profile/api-tokens",
                json={
                    "label": "test-token",
                    "expiry": (
                        datetime.now(timezone.utc) + timedelta(days=1)
                    ).isoformat(),
                },
                ssl=False,
            )
            resp.raise_for_status()
            user_token = (await resp.json())["secret"]

        server = f"https://127.0.0.1:{shared_wg.kubernetes_port}/{token_target_name}"
        kubeconf = processes.ctx.tmpdir / f"kubeconfig-{uuid.uuid4()}.yaml"
        kubeconf.write_text("apiVersion: v1\nkind: Config\n")
        # run from within container when talking to k3s directly
        p = run_kubectl([
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
        ])
        assert p.returncode == 0, "mtls upstream token-user combo failed"
