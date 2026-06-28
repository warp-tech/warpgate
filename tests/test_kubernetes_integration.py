from datetime import datetime, timezone, timedelta
import base64
import hashlib
import html
import re
import secrets
import time
import uuid
import subprocess
from urllib.parse import parse_qs, urlencode, urlparse

import requests

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import aiohttp
import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess, K3sInstance
from .util import alloc_port, wait_port


def run_kubectl(args, **kwargs):
    return subprocess.run(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs
    )


# ---------------------------------------------------------------------------
# OIDC helpers
# ---------------------------------------------------------------------------

# Mirrors the client registered by conftest.start_oidc_server.
OIDC_CLIENT_ID = "warpgate-test"
OIDC_CLIENT_SECRET = "warpgate-test-secret"
# A second OIDC client that simulates kubectl's own client-id.
# Its tokens have aud == KUBECTL_CLIENT_ID (not warpgate-test).
KUBECTL_CLIENT_ID = "kubectl-client"
KUBECTL_CLIENT_SECRET = "kubectl-client-secret"
# Used as the OIDC redirect_uri for our own (non-warpgate) authorization-code
# flow.  We register it explicitly with the mock so the token exchange below
# validates the redirect_uri.  Warpgate never sees this URL.  The mock's
# redirect-uri validator requires an https URL with an explicit port, so we
# derive it from an allocated port (a real listener is never needed).
def _oidc_test_redirect_uri(port):
    return f"https://127.0.0.1:{port}/oidc-test-callback"


def _make_oidc_sso_provider_config(
    oidc_port,
    *,
    auto_create_users=False,
    role_mappings=None,
    additional_trusted_audiences=None,
):
    """Build an ``sso_providers`` config entry pointing at the OIDC mock.

    Mirrors ``_make_sso_provider_config`` in ``test_http_user_auth_oidc.py`` but
    kept local to avoid cross-test coupling.
    """
    provider = {
        "type": "custom",
        "client_id": OIDC_CLIENT_ID,
        "client_secret": OIDC_CLIENT_SECRET,
        "issuer_url": f"http://localhost:{oidc_port}",
        "scopes": [
            "openid",
            "email",
            "profile",
            "preferred_username",
            "warpgate_roles",
        ],
    }
    if role_mappings is not None:
        provider["role_mappings"] = role_mappings
    if additional_trusted_audiences is not None:
        provider["additional_trusted_audiences"] = additional_trusted_audiences
    return {
        "name": "test-oidc",
        "label": "OIDC Test",
        "provider": provider,
        "auto_create_users": auto_create_users,
        # Opt this provider into Kubernetes OIDC bearer auth. The auth path is
        # gated on the presence of this block; the client_id is only used for
        # kubeconfig generation, not for token validation.
        "kubernetes": {
            "client_id": KUBECTL_CLIENT_ID,
        },
    }


def _obtain_oidc_id_token(
    oidc_port,
    redirect_uri,
    *,
    username="User1",
    password="pwd",
    client_id=OIDC_CLIENT_ID,
    client_secret=OIDC_CLIENT_SECRET,
):
    """Drive a self-contained OIDC authorization-code flow against the mock and
    return a raw ID token (JWT string).

    This intentionally does NOT go through Warpgate's ``/sso/start`` endpoint:
    we run our own authorization request (with our own ``redirect_uri`` and a
    self-managed PKCE pair) so we can intercept the authorization ``code`` and
    exchange it ourselves at the token endpoint.  The resulting token has
    ``aud == <client_id>`` (default: ``warpgate-test``), which is what
    Warpgate's Kubernetes Bearer-auth path validates against.
    """
    issuer = f"http://localhost:{oidc_port}"
    disco = requests.get(
        f"{issuer}/.well-known/openid-configuration", timeout=10
    ).json()
    authorization_endpoint = disco["authorization_endpoint"]
    token_endpoint = disco["token_endpoint"]

    session = requests.Session()

    # The mock client requires PKCE, so generate a verifier/challenge pair.
    code_verifier = (
        base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    )
    code_challenge = (
        base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        )
        .rstrip(b"=")
        .decode()
    )

    # 1. Authorization request -> mock login page
    auth_params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile preferred_username warpgate_roles",
        "state": uuid.uuid4().hex,
        "nonce": uuid.uuid4().hex,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    auth_url = f"{authorization_endpoint}?{urlencode(auth_params)}"
    resp = session.get(auth_url)
    assert resp.status_code == 200, (
        f"authorize failed: {resp.status_code} {resp.text[:300]}"
    )

    login_page_url = resp.url
    login_html = resp.text

    token_match = re.search(
        r'name="__RequestVerificationToken"[^>]*value="([^"]*)"',
        login_html,
    )
    assert token_match, f"no anti-forgery token in login form: {login_html[:300]}"
    verification_token = html.unescape(token_match.group(1))

    m = re.search(r'name="Input.ReturnUrl"[^>]*value="([^"]*)"', login_html)
    assert m, "no ReturnUrl in login form"
    return_url = html.unescape(m.group(1))

    # 2. Submit credentials
    resp = session.post(
        login_page_url,
        data={
            "Input.Username": username,
            "Input.Password": password,
            "Input.Button": "login",
            "Input.ReturnUrl": return_url,
            "__RequestVerificationToken": verification_token,
        },
        allow_redirects=False,
    )

    # 3. Chase redirects until the mock sends us back to our redirect_uri
    code = None
    for _ in range(15):
        if resp.status_code // 100 != 3:
            break
        location = resp.headers["Location"]
        if location.startswith("/"):
            location = f"{issuer}{location}"
        if location.startswith(redirect_uri):
            qs = parse_qs(urlparse(location).query)
            assert "code" in qs, f"no code in callback: {location}"
            code = qs["code"][0]
            break
        resp = session.get(location, allow_redirects=False)

    assert code is not None, (
        "OIDC mock did not redirect back with an authorization code"
    )

    # 4. Exchange the code for tokens
    token_resp = requests.post(
        token_endpoint,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
            "code_verifier": code_verifier,
        },
        timeout=10,
    )
    assert token_resp.status_code == 200, (
        f"token exchange failed: {token_resp.status_code} {token_resp.text[:300]}"
    )
    body = token_resp.json()
    id_token = body.get("id_token")
    assert id_token, f"no id_token in token response: {body}"
    return id_token


def _obtain_kubectl_client_id_token(oidc_port, redirect_uri, *, username="User1", password="pwd"):
    """Like _obtain_oidc_id_token but uses KUBECTL_CLIENT_ID as the client.

    The resulting ID token will have ``aud == kubectl-client``, which is NOT
    Warpgate's primary client_id (``warpgate-test``).  This exercises the
    ``additional_trusted_audiences`` path: the token is only accepted when
    ``kubectl-client`` is in the provider's ``additional_trusted_audiences`` list.
    """
    return _obtain_oidc_id_token(
        oidc_port,
        redirect_uri,
        username=username,
        password=password,
        client_id=KUBECTL_CLIENT_ID,
        client_secret=KUBECTL_CLIENT_SECRET,
    )


def _oidc_user_with_roles(roles):
    """OIDC mock user config carrying the given warpgate_roles claim values."""
    claims = [
        {"Type": "name", "Value": "Sam Tailor", "ValueType": "string"},
        {"Type": "email", "Value": "sam.tailor@gmail.com", "ValueType": "string"},
        {
            "Type": "preferred_username",
            "Value": "sam_tailor",
            "ValueType": "string",
        },
    ]
    for r in roles:
        claims.append(
            {"Type": "warpgate_roles", "Value": r, "ValueType": "string"}
        )
    return [
        {
            "SubjectId": "1",
            "Username": "User1",
            "Password": "pwd",
            "Claims": claims,
        }
    ]


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

    # -- OIDC Bearer authentication ----------------------------------------

    def _start_oidc_mock_for_roles(self, processes: ProcessManager, roles):
        """Start the OIDC mock server pre-configured with a user carrying the
        given ``warpgate_roles`` claim values.

        Returns ``(oidc_port, redirect_uri)`` where ``redirect_uri`` is a
        registered callback URL suitable for use in the authorization-code flow.
        """
        wg_http_port = alloc_port()
        redirect_uri = _oidc_test_redirect_uri(alloc_port())
        oidc_port = processes.start_oidc_server(
            wg_http_port,
            extra_scopes=["warpgate_roles"],
            users_override=_oidc_user_with_roles(roles),
            extra_identity_resources=[
                {"Name": "warpgate_roles", "ClaimTypes": ["warpgate_roles"]},
            ],
            redirect_uris=[redirect_uri],
        )
        return oidc_port, redirect_uri

    def _start_oidc_mock_for_roles_with_kubectl_client(
        self, processes: ProcessManager, roles
    ):
        """Like ``_start_oidc_mock_for_roles`` but also registers a second OIDC
        client ``kubectl-client`` that simulates the kubectl exec-plugin audience.

        Returns ``(oidc_port, primary_redirect_uri, kubectl_redirect_uri)``
        where ``kubectl_redirect_uri`` is registered for ``KUBECTL_CLIENT_ID``.
        """
        wg_http_port = alloc_port()
        primary_redirect_uri = _oidc_test_redirect_uri(alloc_port())
        kubectl_redirect_uri = _oidc_test_redirect_uri(alloc_port())

        # The extra client mirrors warpgate-test but with a different client_id.
        # It shares the same allowed scopes and always includes user claims in
        # the ID token so the Kubernetes OIDC path can read them without userinfo.
        kubectl_client_entry = {
            "ClientId": KUBECTL_CLIENT_ID,
            "ClientSecrets": [KUBECTL_CLIENT_SECRET],
            "AllowedGrantTypes": ["authorization_code"],
            "AllowedScopes": [
                "openid",
                "profile",
                "email",
                "preferred_username",
                "warpgate_roles",
            ],
            "ClientClaimsPrefix": "",
            "AlwaysIncludeUserClaimsInIdToken": True,
            "RedirectUris": [kubectl_redirect_uri],
        }

        oidc_port = processes.start_oidc_server(
            wg_http_port,
            extra_scopes=["warpgate_roles"],
            users_override=_oidc_user_with_roles(roles),
            extra_identity_resources=[
                {"Name": "warpgate_roles", "ClaimTypes": ["warpgate_roles"]},
            ],
            redirect_uris=[primary_redirect_uri],
            extra_clients=[kubectl_client_entry],
        )
        return oidc_port, primary_redirect_uri, kubectl_redirect_uri

    def _start_wg_and_k3s_target(
        self,
        processes: ProcessManager,
        *,
        oidc_port,
        role_mappings,
        target_role_name,
    ):
        """Start a dedicated warpgate wired to the OIDC mock and a token-auth
        Kubernetes target backed by k3s.

        Returns ``(wg, target_name, k3s)``.  A role named ``target_role_name``
        is created, granted access to the target, and used as a mapping value
        for the OIDC ``warpgate_roles`` claim per ``role_mappings``.
        """
        k3s = processes.start_k3s()

        wg = processes.start_wg(
            config_patch={
                "sso_providers": [
                    _make_oidc_sso_provider_config(
                        oidc_port,
                        auto_create_users=True,
                        role_mappings=role_mappings,
                    )
                ],
            },
        )
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        url = f"https://localhost:{wg.http_port}"

        target_name = f"k8s-oidc-{uuid.uuid4()}"
        with admin_client(url) as api:
            role = api.create_role(
                sdk.RoleDataRequest(name=target_role_name)
            )
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=target_name,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetKubernetesOptions(
                            kind="Kubernetes",
                            cluster_url=f"https://127.0.0.1:{k3s.port}",
                            tls=sdk.Tls(
                                mode=sdk.TlsMode.PREFERRED, verify=False
                            ),
                            auth=sdk.KubernetesTargetAuth(
                                sdk.KubernetesTargetAuthKubernetesTargetTokenAuth(
                                    kind="Token", token=k3s.token
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(target.id, role.id)

        return wg, target_name, k3s

    @pytest.mark.asyncio
    async def test_kubectl_oidc_bearer_authenticates(
        self, processes: ProcessManager
    ):
        """A valid OIDC ID token for an authorized user -> 200."""
        target_role = f"k8s-oidc-role-{uuid.uuid4()}"
        oidc_port, redirect_uri = self._start_oidc_mock_for_roles(
            processes, ["k8s-users"]
        )

        wg, target_name, _k3s = self._start_wg_and_k3s_target(
            processes,
            oidc_port=oidc_port,
            role_mappings={"k8s-users": target_role},
            target_role_name=target_role,
        )

        id_token = _obtain_oidc_id_token(oidc_port, redirect_uri)

        resp = requests.get(
            f"https://localhost:{wg.kubernetes_port}/{target_name}/version",
            headers={"Authorization": f"Bearer {id_token}"},
            verify=False,
        )
        assert resp.status_code == 200, (
            f"expected 200, got {resp.status_code}: {resp.text[:300]}"
        )

    @pytest.mark.asyncio
    async def test_kubectl_oidc_invalid_token_rejected(
        self, processes: ProcessManager
    ):
        """A garbage / unverifiable Bearer token -> 401.

        The Rust auth path (auth.rs) only performs target lookup *after* a token
        has been validated (as an API token or a verifiable OIDC ID token).  A
        garbage token exhausts both checks and hits the final 401 before any
        target or k3s lookup, so neither k3s nor a Kubernetes target is needed.
        """
        oidc_port, _ = self._start_oidc_mock_for_roles(processes, ["k8s-users"])

        # Start warpgate with an SSO provider so the OIDC path is exercised,
        # but skip k3s and target creation — auth fails before target lookup.
        wg = processes.start_wg(
            config_patch={
                "sso_providers": [
                    _make_oidc_sso_provider_config(oidc_port)
                ],
            },
        )
        wait_port(wg.http_port, for_process=wg.process, recv=False)

        # An unsigned/garbage JWT - neither a valid API token nor a verifiable
        # OIDC ID token, so authentication must fail outright.
        bad_token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJub2JvZHkifQ.bogus"
        resp = requests.get(
            f"https://localhost:{wg.kubernetes_port}/some-target/version",
            headers={"Authorization": f"Bearer {bad_token}"},
            verify=False,
        )
        assert resp.status_code == 401, (
            f"expected 401, got {resp.status_code}: {resp.text[:300]}"
        )

    @pytest.mark.asyncio
    async def test_kubectl_oidc_unauthorized_user_forbidden(
        self, processes: ProcessManager
    ):
        """A valid OIDC token whose roles do NOT grant access -> 403."""
        target_role = f"k8s-oidc-role-{uuid.uuid4()}"
        # The OIDC user carries "other-team", but the target only grants the
        # role mapped from "k8s-users".  "other-team" maps to an unrelated role
        # that is never authorized on the target, so the user authenticates but
        # is not authorized.
        unrelated_role = f"k8s-oidc-unrelated-{uuid.uuid4()}"
        oidc_port, redirect_uri = self._start_oidc_mock_for_roles(
            processes, ["other-team"]
        )

        wg, target_name, _k3s = self._start_wg_and_k3s_target(
            processes,
            oidc_port=oidc_port,
            role_mappings={
                "k8s-users": target_role,
                "other-team": unrelated_role,
            },
            target_role_name=target_role,
        )
        # Make sure the unrelated role exists so the mapping resolves but it is
        # never granted on the target.
        with admin_client(f"https://localhost:{wg.http_port}") as api:
            api.create_role(sdk.RoleDataRequest(name=unrelated_role))

        id_token = _obtain_oidc_id_token(oidc_port, redirect_uri)

        resp = requests.get(
            f"https://localhost:{wg.kubernetes_port}/{target_name}/version",
            headers={"Authorization": f"Bearer {id_token}"},
            verify=False,
        )
        assert resp.status_code == 403, (
            f"expected 403, got {resp.status_code}: {resp.text[:300]}"
        )

    @pytest.mark.asyncio
    async def test_kubectl_oidc_trusted_audience_accepted(
        self, processes: ProcessManager
    ):
        """A valid OIDC ID token whose aud is a separately-registered kubectl
        client (not Warpgate's own client_id) is accepted when that client id
        is listed in ``additional_trusted_audiences``.

        The OIDC mock issues a token with ``aud == kubectl-client``; Warpgate's
        primary ``client_id`` is ``warpgate-test``.  Because ``kubectl-client``
        is in ``additional_trusted_audiences``, the token must be accepted (200).
        """
        target_role = f"k8s-oidc-role-{uuid.uuid4()}"
        oidc_port, primary_redirect_uri, kubectl_redirect_uri = (
            self._start_oidc_mock_for_roles_with_kubectl_client(
                processes, ["k8s-users"]
            )
        )

        k3s = processes.start_k3s()

        # Warpgate config: client_id = warpgate-test, but kubectl-client is trusted.
        wg = processes.start_wg(
            config_patch={
                "sso_providers": [
                    _make_oidc_sso_provider_config(
                        oidc_port,
                        auto_create_users=True,
                        role_mappings={"k8s-users": target_role},
                        additional_trusted_audiences=[KUBECTL_CLIENT_ID],
                    )
                ],
            },
        )
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        url = f"https://localhost:{wg.http_port}"

        target_name = f"k8s-oidc-trusted-aud-{uuid.uuid4()}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=target_role))
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=target_name,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetKubernetesOptions(
                            kind="Kubernetes",
                            cluster_url=f"https://127.0.0.1:{k3s.port}",
                            tls=sdk.Tls(mode=sdk.TlsMode.PREFERRED, verify=False),
                            auth=sdk.KubernetesTargetAuth(
                                sdk.KubernetesTargetAuthKubernetesTargetTokenAuth(
                                    kind="Token", token=k3s.token
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(target.id, role.id)

        # Obtain a token issued for kubectl-client (aud == kubectl-client).
        id_token = _obtain_kubectl_client_id_token(oidc_port, kubectl_redirect_uri)

        resp = requests.get(
            f"https://localhost:{wg.kubernetes_port}/{target_name}/version",
            headers={"Authorization": f"Bearer {id_token}"},
            verify=False,
        )
        assert resp.status_code == 200, (
            f"expected 200 for trusted audience, got {resp.status_code}: {resp.text[:300]}"
        )

    @pytest.mark.asyncio
    async def test_kubectl_oidc_untrusted_audience_rejected(
        self, processes: ProcessManager
    ):
        """A valid OIDC ID token whose aud is NOT in ``additional_trusted_audiences``
        and is NOT Warpgate's ``client_id`` must be rejected (401).

        This is the negative case for the trusted-audience path: ``kubectl-client``
        is a registered OIDC client (so the token is cryptographically valid), but
        it is NOT listed in ``additional_trusted_audiences``.  Authentication must
        fail before any target lookup.
        """
        oidc_port, _primary_redirect_uri, kubectl_redirect_uri = (
            self._start_oidc_mock_for_roles_with_kubectl_client(
                processes, ["k8s-users"]
            )
        )

        # Warpgate: client_id = warpgate-test, NO additional_trusted_audiences.
        wg = processes.start_wg(
            config_patch={
                "sso_providers": [
                    _make_oidc_sso_provider_config(oidc_port)
                    # additional_trusted_audiences intentionally omitted
                ],
            },
        )
        wait_port(wg.http_port, for_process=wg.process, recv=False)

        # Token with aud == kubectl-client (valid JWT, but wrong audience).
        id_token = _obtain_kubectl_client_id_token(oidc_port, kubectl_redirect_uri)

        resp = requests.get(
            f"https://localhost:{wg.kubernetes_port}/some-target/version",
            headers={"Authorization": f"Bearer {id_token}"},
            verify=False,
        )
        assert resp.status_code == 401, (
            f"expected 401 for untrusted audience, got {resp.status_code}: {resp.text[:300]}"
        )
