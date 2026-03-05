from datetime import datetime, timezone, timedelta
import time
import uuid
import subprocess

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import aiohttp
import pytest

from .api_client import admin_client, sdk
from .conftest import WarpgateProcess, K3sInstance


def run_kubectl(args, **kwargs):
    return subprocess.run(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs
    )


class TestKubernetesIntegration:
    @pytest.mark.asyncio
    async def test_kubectl_through_warpgate(
        self, processes, shared_wg: WarpgateProcess
    ):
        # start k3s and obtain a service-account token
        k3s = processes.start_k3s()
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
        assert p.returncode == 0, f"should accept the correct token: {p.stderr!r}"

        # negative token case
        bad_cmd = token_cmd.copy()
        bad_cmd[bad_cmd.index(user_token)] = user_token + "x"
        p = run_kubectl(bad_cmd)
        assert p.returncode != 0, "should not accept an invalid token"

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
        assert p.returncode == 0, f"should accept the valid certificate: {p.stderr!r}"

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
        assert p.returncode != 0, "should not accept an unknown certificate"

    @pytest.mark.asyncio
    async def test_kubectl_run(self, processes, shared_wg: WarpgateProcess):
        """Ensure that write requests such as ``kubectl run`` are proxied."""
        k3s: K3sInstance = processes.start_k3s()
        k3s_port = k3s.port
        k3s_token = k3s.token
        url = f"https://localhost:{shared_wg.http_port}"

        # create user/role as before
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid.uuid4()}"))
            user = api.create_user(
                sdk.CreateUserRequest(username=f"user-{uuid.uuid4()}")
            )
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id)

        target_name = f"k8s-run-{uuid.uuid4()}"
        with admin_client(url) as api:
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=target_name,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetKubernetesOptions(
                            kind="Kubernetes",
                            cluster_url=f"https://127.0.0.1:{k3s_port}",
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
            api.add_target_role(target.id, role.id)

        # login and request api token
        async with aiohttp.ClientSession() as session:
            resp = await session.post(
                f"{url}/@warpgate/api/auth/login",
                json={"username": user.username, "password": "123"},
                ssl=False,
            )
            resp.raise_for_status()
            resp = await session.post(
                f"{url}/@warpgate/api/profile/api-tokens",
                json={
                    "label": "run-token",
                    "expiry": (
                        datetime.now(timezone.utc) + timedelta(days=1)
                    ).isoformat(),
                },
                ssl=False,
            )
            resp.raise_for_status()
            user_token = (await resp.json())["secret"]

        server = f"https://127.0.0.1:{shared_wg.kubernetes_port}/{target_name}"
        # use interactive tty and echo some data through cat to ensure
        # stdin/stdout forwarding works for ``kubectl run`` as well
        run_cmd = [
            "kubectl",
            "run",
            "-v9",
            "--server",
            server,
            "--insecure-skip-tls-verify",
            "--token",
            user_token,
            "-n",
            "default",
            "test-cat",
            "--image=alpine:3",
            "--restart=Never",
            "-i",
            "--rm",
            "--command",
            "--",
            "cat",
        ]
        p = run_kubectl(
            run_cmd,
            input=b"hello-from-run\n",
            timeout=120,
        )
        assert p.returncode == 0, f"kubectl run should succeed: {p.stderr!r}"
        assert b"hello-from-run" in p.stdout, (
            f"run stdout did not contain expected text: {p.stdout!r}"
        )

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
        assert mtls_cert and "BEGIN CERTIFICATE" in mtls_cert, (
            "upstream cert missing or invalid"
        )
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
        p = run_kubectl(
            [
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
        )
        assert p.returncode == 0, "mtls upstream token-user combo failed"

    @pytest.mark.asyncio
    async def test_kubectl_exec_io(self, processes, shared_wg: WarpgateProcess):
        """Verify that ``kubectl exec`` through Warpgate proxies stdin/stdout."""
        k3s: K3sInstance = processes.start_k3s()
        k3s_port = k3s.port
        k3s_token = k3s.token
        url = f"https://localhost:{shared_wg.http_port}"

        # --- set up user, role, target ---
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid.uuid4()}"))
            user = api.create_user(
                sdk.CreateUserRequest(username=f"user-{uuid.uuid4()}")
            )
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id)

        target_name = f"k8s-exec-{uuid.uuid4()}"
        with admin_client(url) as api:
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=target_name,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetKubernetesOptions(
                            kind="Kubernetes",
                            cluster_url=f"https://127.0.0.1:{k3s_port}",
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
            api.add_target_role(target.id, role.id)

        # login and obtain a user API token
        async with aiohttp.ClientSession() as session:
            resp = await session.post(
                f"{url}/@warpgate/api/auth/login",
                json={"username": user.username, "password": "123"},
                ssl=False,
            )
            resp.raise_for_status()
            resp = await session.post(
                f"{url}/@warpgate/api/profile/api-tokens",
                json={
                    "label": "exec-token",
                    "expiry": (
                        datetime.now(timezone.utc) + timedelta(days=1)
                    ).isoformat(),
                },
                ssl=False,
            )
            resp.raise_for_status()
            user_token = (await resp.json())["secret"]

        server = f"https://127.0.0.1:{shared_wg.kubernetes_port}/{target_name}"

        # create a simple pod inside k3s
        pod_name = f"exec-test-{uuid.uuid4().hex[:8]}"
        pod_yaml = (
            f"apiVersion: v1\n"
            f"kind: Pod\n"
            f"metadata:\n"
            f"  name: {pod_name}\n"
            f"  namespace: default\n"
            f"spec:\n"
            f"  containers:\n"
            f"  - name: alpine\n"
            f"    image: alpine:3\n"
            f"    command: ['sleep', '3600']\n"
        )
        k3s.kubectl(["apply", "-f", "-"], input=pod_yaml.encode())

        # wait for the pod to be Running
        for _ in range(120):
            r = k3s.kubectl(
                [
                    "get",
                    "pod",
                    pod_name,
                    "-n",
                    "default",
                    "-o",
                    "jsonpath={.status.phase}",
                ],
                check=False,
            )
            if r.stdout.strip() == b"Running":
                break
            time.sleep(1)
        else:
            raise AssertionError(
                f"pod {pod_name} did not reach Running: {r.stdout!r} {r.stderr!r}"
            )

        # --- kubectl exec: send stdin and read stdout ---
        p = run_kubectl(
            [
                "kubectl",
                "--server",
                server,
                "--insecure-skip-tls-verify",
                "--token",
                user_token,
                "exec",
                "-i",
                "-n",
                "default",
                pod_name,
                "--",
                "cat",
            ],
            input=b"hello-from-exec\n",
            timeout=30,
        )
        assert p.returncode == 0, f"kubectl exec failed: {p.stderr!r}"
        assert b"hello-from-exec" in p.stdout, (
            f"exec stdout did not contain expected text: {p.stdout!r}"
        )

    @pytest.mark.asyncio
    async def test_kubectl_attach_io(self, processes, shared_wg: WarpgateProcess):
        """Verify that ``kubectl attach`` through Warpgate proxies stdin/stdout."""
        k3s: K3sInstance = processes.start_k3s()
        k3s_port = k3s.port
        k3s_token = k3s.token
        url = f"https://localhost:{shared_wg.http_port}"

        # --- set up user, role, target ---
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid.uuid4()}"))
            user = api.create_user(
                sdk.CreateUserRequest(username=f"user-{uuid.uuid4()}")
            )
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id)

        target_name = f"k8s-attach-{uuid.uuid4()}"
        with admin_client(url) as api:
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=target_name,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetKubernetesOptions(
                            kind="Kubernetes",
                            cluster_url=f"https://127.0.0.1:{k3s_port}",
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
            api.add_target_role(target.id, role.id)

        # login and obtain a user API token
        async with aiohttp.ClientSession() as session:
            resp = await session.post(
                f"{url}/@warpgate/api/auth/login",
                json={"username": user.username, "password": "123"},
                ssl=False,
            )
            resp.raise_for_status()
            resp = await session.post(
                f"{url}/@warpgate/api/profile/api-tokens",
                json={
                    "label": "attach-token",
                    "expiry": (
                        datetime.now(timezone.utc) + timedelta(days=1)
                    ).isoformat(),
                },
                ssl=False,
            )
            resp.raise_for_status()
            user_token = (await resp.json())["secret"]

        server = f"https://127.0.0.1:{shared_wg.kubernetes_port}/{target_name}"

        # create a pod whose main process reads stdin and echoes it back
        pod_name = f"attach-test-{uuid.uuid4().hex[:8]}"
        pod_yaml = (
            f"apiVersion: v1\n"
            f"kind: Pod\n"
            f"metadata:\n"
            f"  name: {pod_name}\n"
            f"  namespace: default\n"
            f"spec:\n"
            f"  containers:\n"
            f"  - name: cat\n"
            f"    image: alpine:3\n"
            f"    command: ['cat']\n"
            f"    stdin: true\n"
            f"    stdinOnce: true\n"
        )
        k3s.kubectl(["apply", "-f", "-"], input=pod_yaml.encode())

        # wait for the pod to be Running
        for _ in range(120):
            r = k3s.kubectl(
                [
                    "get",
                    "pod",
                    pod_name,
                    "-n",
                    "default",
                    "-o",
                    "jsonpath={.status.phase}",
                ],
                check=False,
            )
            if r.stdout.strip() == b"Running":
                break
            time.sleep(1)
        else:
            raise AssertionError(
                f"pod {pod_name} did not reach Running: {r.stdout!r} {r.stderr!r}"
            )

        # --- kubectl attach: send stdin and read stdout ---
        p = run_kubectl(
            [
                "kubectl",
                "-v9",
                "--server",
                server,
                "--insecure-skip-tls-verify",
                "--token",
                user_token,
                "attach",
                "-i",
                "-n",
                "default",
                pod_name,
            ],
            input=b"hello-from-attach\n",
            timeout=30,
        )
        assert p.returncode == 0, f"kubectl attach failed: {p.stderr!r}"
        assert b"hello-from-attach" in p.stdout, (
            f"attach stdout did not contain expected text: {p.stdout!r}"
        )
