import logging
import os
import time
import psutil
import pytest
import requests
import shutil
import signal
import subprocess
import tempfile
import urllib3
import uuid
import base64

# cryptography is used to generate client certificates/CSRs locally
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent
from typing import List, Optional

from deepmerge import always_merger

from .util import _wait_timeout, alloc_port, wait_port
from .test_http_common import echo_server_port  # noqa


cargo_root = Path(os.getcwd()).parent
enable_coverage = os.getenv("ENABLE_COVERAGE", "0") == "1"
binary_path = (
    "target/llvm-cov-target/debug/warpgate"
    if enable_coverage
    else "target/debug/warpgate"
)


@dataclass
class Context:
    tmpdir: Path


@dataclass
class K3sInstance:
    port: int
    token: str
    container_name: str
    client_cert: str
    client_key: str

    def kubectl(self, cmd_args, input=None, check=True):
        ret = subprocess.run(
            ["docker", "exec", "-i", self.container_name, "kubectl", *cmd_args],
            input=input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if check:
            try:
                ret.check_returncode()
            except subprocess.CalledProcessError as e:
                logging.error(
                    f"kubectl command failed: {' '.join(cmd_args)}\nstdout: {e.stdout.decode()}\nstderr: {e.stderr.decode()}"
                )
                raise
        return ret


@dataclass
class VaultInstance:
    """A dev-mode Vault or OpenBao server running in Docker.

    OpenBao is a Vault fork that keeps the same HTTP API, so this single class -- and its
    kv_put/kv_get/AppRole helpers -- talks to either one identically; only `start_vault()`'s
    `engine` argument picks which server actually gets started.

    Talks to the server's HTTP API directly (root token auth) so tests can seed/inspect KV v2
    secrets independently of Warpgate, and set up AppRole auth for backend-auth tests.
    """

    port: int
    root_token: str
    container_name: str
    backend_type: str = "vault"

    @property
    def addr(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _headers(self):
        return {"X-Vault-Token": self.root_token}

    def kv_put(self, mount: str, path: str, **fields):
        r = requests.put(
            f"{self.addr}/v1/{mount}/data/{path}",
            json={"data": fields},
            headers=self._headers(),
        )
        r.raise_for_status()
        return r.json()

    def kv_get(self, mount: str, path: str):
        """Returns (data, version) for the current version of a KV v2 secret."""
        r = requests.get(
            f"{self.addr}/v1/{mount}/data/{path}",
            headers=self._headers(),
        )
        r.raise_for_status()
        body = r.json()["data"]
        return body["data"], body["metadata"]["version"]

    def enable_approle(self):
        r = requests.post(
            f"{self.addr}/v1/sys/auth/approle",
            json={"type": "approle"},
            headers=self._headers(),
        )
        # 400 => already enabled (harmless if a previous call in the same container did this)
        if r.status_code not in (204, 400):
            r.raise_for_status()

    def create_approle_role(self, role_name: str, policy_hcl: str):
        """Creates a policy + AppRole role using it, returns (role_id, secret_id)."""
        r = requests.put(
            f"{self.addr}/v1/sys/policies/acl/{role_name}",
            json={"policy": policy_hcl},
            headers=self._headers(),
        )
        r.raise_for_status()

        r = requests.post(
            f"{self.addr}/v1/auth/approle/role/{role_name}",
            json={"token_policies": [role_name]},
            headers=self._headers(),
        )
        r.raise_for_status()

        r = requests.get(
            f"{self.addr}/v1/auth/approle/role/{role_name}/role-id",
            headers=self._headers(),
        )
        r.raise_for_status()
        role_id = r.json()["data"]["role_id"]

        r = requests.post(
            f"{self.addr}/v1/auth/approle/role/{role_name}/secret-id",
            headers=self._headers(),
        )
        r.raise_for_status()
        secret_id = r.json()["data"]["secret_id"]

        return role_id, secret_id


@dataclass
class Child:
    process: subprocess.Popen
    stop_signal: signal.Signals
    stop_timeout: float


# Geometry of the e2e VNC backend (images/vnc-server); passed to the container and
# asserted by the VNC tests as the size the relay resizes the viewer to.
VNC_BACKEND_SIZE = (800, 600)

# Framebuffer size Warpgate's RDP helper requests from the target (see
# warpgate-protocol-rdp `connect()`), i.e. the size desktop frames arrive at.
RDP_BACKEND_SIZE = (1280, 800)


@dataclass
class WarpgateProcess:
    config_path: Path
    process: subprocess.Popen
    http_port: int
    ssh_port: int
    mysql_port: int
    postgres_port: int
    kubernetes_port: int
    vnc_port: int
    rdp_port: int


class ProcessManager:
    children: List[Child]

    def __init__(self, ctx: Context, timeout: int) -> None:
        self.children = []
        self.ctx = ctx
        self.timeout = timeout
        self._k3s_containers: List[str] = []

    def _remove_k3s_containers(self):
        """Force-remove every k3s container we've started so far. Idempotent —
        `docker rm -f` on an already-gone container is a harmless no-op."""
        for name in self._k3s_containers:
            subprocess.run(
                ["docker", "rm", "-f", name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        self._k3s_containers.clear()

    def stop(self):
        self._remove_k3s_containers()
        for child in self.children:
            try:
                p = psutil.Process(child.process.pid)
            except psutil.NoSuchProcess:
                continue

            p.send_signal(child.stop_signal)

            for sp in p.children(recursive=True):
                try:
                    sp.terminate()
                except psutil.NoSuchProcess:
                    pass

            try:
                p.wait(timeout=child.stop_timeout)
            except psutil.TimeoutExpired:
                for sp in p.children(recursive=True):
                    try:
                        sp.kill()
                    except psutil.NoSuchProcess:
                        pass
                p.kill()

    def start_ssh_server(self, trusted_keys=[], extra_config="", root_password=None):
        port = alloc_port()
        data_dir = self.ctx.tmpdir / f"sshd-{uuid.uuid4()}"
        data_dir.mkdir(parents=True)
        authorized_keys_path = data_dir / "authorized_keys"
        authorized_keys_path.write_text("\n".join(trusted_keys))
        config_path = data_dir / "sshd_config"
        if root_password:
            # the base image only unlocks the root account (empty password); a real
            # password + explicit PasswordAuthentication is needed for password-auth tests
            extra_config = f"PasswordAuthentication yes\n{extra_config}"
        config_path.write_text(
            dedent(
                f"""\
                Port 22
                AuthorizedKeysFile {authorized_keys_path}
                AllowAgentForwarding yes
                AllowTcpForwarding yes
                GatewayPorts yes
                X11Forwarding yes
                UseDNS no
                PermitTunnel yes
                StrictModes no
                PermitRootLogin yes
                HostKey /ssh-keys/id_ed25519
                Subsystem	sftp	/usr/lib/ssh/sftp-server
                LogLevel DEBUG3
                {extra_config}
                """
            )
        )
        data_dir.chmod(0o700)
        authorized_keys_path.chmod(0o600)
        config_path.chmod(0o600)

        container_name = f"warpgate-e2e-ssh-server-{uuid.uuid4()}"
        self.start(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                container_name,
                "-p",
                f"{port}:22",
                "-v",
                f"{data_dir}:{data_dir}",
                "-v",
                f"{os.getcwd()}/ssh-keys:/ssh-keys",
                "warpgate-e2e-ssh-server",
                "-f",
                str(config_path),
            ]
        )

        if root_password:

            def set_root_password():
                while True:
                    # busybox's `passwd` (no `shadow` package in this image) prompts for the
                    # new password twice on stdin; feed both lines via `docker exec -i`.
                    r = subprocess.run(
                        ["docker", "exec", "-i", container_name, "passwd", "root"],
                        input=f"{root_password}\n{root_password}\n".encode(),
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    if r.returncode == 0:
                        break
                    time.sleep(0.5)

            _wait_timeout(
                set_root_password,
                "could not set root password in ssh-server container",
                timeout=self.timeout,
            )

        return port

    def start_mariadb_server(self):
        port = alloc_port()
        self.start(
            ["docker", "run", "--rm", "-p", f"{port}:3306", "warpgate-e2e-mariadb-server"]
        )
        return port

    def start_mysql_server(self):
        port = alloc_port()
        self.start(
            ["docker", "run", "--rm", "-p", f"{port}:3306", "warpgate-e2e-mysql-server"]
        )
        return port

    def start_vnc_server(self, require_password=False):
        port = alloc_port()
        args = [
            "docker",
            "run",
            "--rm",
            "--name",
            f"warpgate-e2e-vnc-server-{uuid.uuid4()}",
            "-p",
            f"{port}:5900",
            "-e",
            f"VNC_GEOMETRY={VNC_BACKEND_SIZE[0]}x{VNC_BACKEND_SIZE[1]}",
        ]
        if require_password:
            args += ["-e", "VNC_SECURITY=VncAuth", "-e", "VNC_PASSWORD=123"]
        args.append("warpgate-e2e-vnc-server")
        self.start(args)
        return port

    def start_rdp_server(self):
        # Headless RDP backend (images/rdp-server) with a fixed login user:pass of
        # `user`:`123`. Warpgate authenticates to it over NLA using the target password.
        port = alloc_port()
        self.start(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                f"warpgate-e2e-rdp-server-{uuid.uuid4()}",
                "-p",
                f"{port}:3389",
                "warpgate-e2e-rdp-server",
            ]
        )
        return port

    def start_postgres_server(self):
        port = alloc_port()
        container_name = f"warpgate-e2e-postgres-server-{uuid.uuid4()}"
        self.start(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                container_name,
                "-p",
                f"{port}:5432",
                "warpgate-e2e-postgres-server",
            ]
        )

        def wait_postgres():
            while True:
                try:
                    subprocess.check_call(
                        [
                            "docker",
                            "exec",
                            container_name,
                            "pg_isready",
                            "-h",
                            "localhost",
                            "-U",
                            "user",
                        ]
                    )
                    break
                except subprocess.CalledProcessError:
                    time.sleep(1)

        _wait_timeout(wait_postgres, "Postgres is not ready", timeout=self.timeout)
        logging.debug(f"Postgres {container_name} is up")
        return port

    def start_k3s(self) -> K3sInstance:
        """
        Runs a privileged k3s container, waits for the API to be ready,
        creates a ServiceAccount and clusterrolebinding, then uses
        `kubectl create token` to fetch the bearer token. Assumes a modern
        k8s version (no fallback logic needed).

        The ProcessManager is session-scoped, so a k3s container would
        otherwise stay up until the whole run ends. Left running, several of
        these heavyweight privileged containers pile up across the k8s tests
        and starve each other; an OOM-killed one is then removed by `--rm` and
        later `docker exec`s fail with "No such container". Only one is ever
        needed at a time, so tear down any earlier k3s before starting a fresh
        one.
        """
        self._remove_k3s_containers()
        port = alloc_port()
        container_name = f"warpgate-e2e-k3s-{uuid.uuid4()}"
        image = os.getenv("K3S_IMAGE", "rancher/k3s:v1.35.2-k3s1")

        self.start(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                container_name,
                "--privileged",
                "-p",
                f"{port}:6443",
                image,
                "server",
                "--disable",
                "traefik",
                "--disable-cloud-controller",
            ]
        )
        self._k3s_containers.append(container_name)

        def wait_k3s():
            # Wait until kube-apiserver is responding
            while True:
                try:
                    subprocess.check_call(
                        [
                            "docker",
                            "exec",
                            container_name,
                            "kubectl",
                            "get",
                            "nodes",
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    break
                except subprocess.CalledProcessError:
                    time.sleep(1)

        _wait_timeout(wait_k3s, "k3s API is not ready", timeout=self.timeout * 5)

        # k3s sometimes returns OK for `get nodes` before namespace controller
        # has created the "default" namespace.  make sure it exists before we
        # try to create objects inside it.
        def wait_default_ns():
            while True:
                r = subprocess.run(
                    [
                        "docker",
                        "exec",
                        container_name,
                        "kubectl",
                        "get",
                        "namespace",
                        "default",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if r.returncode:
                    time.sleep(1)
                else:
                    break

        _wait_timeout(
            wait_default_ns, "default namespace is not ready", timeout=self.timeout * 5
        )

        # Create service account inside the container
        subprocess.check_call(
            [
                "docker",
                "exec",
                container_name,
                "kubectl",
                "create",
                "serviceaccount",
                "test-sa",
                "-n",
                "default",
            ]
        )

        # Assign cluster admin role so our SA can do anything
        subprocess.check_call(
            [
                "docker",
                "exec",
                container_name,
                "kubectl",
                "create",
                "clusterrolebinding",
                "test-sa-binding",
                "--clusterrole=cluster-admin",
                "--serviceaccount=default:test-sa",
            ]
        )

        token = (
            subprocess.check_output(
                [
                    "docker",
                    "exec",
                    container_name,
                    "kubectl",
                    "create",
                    "token",
                    "test-sa",
                    "-n",
                    "default",
                ],
                stderr=subprocess.DEVNULL,
            )
            .decode()
            .strip()
        )

        # generate a client key and CSR locally, then ask the k3s CA to sign it
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "system:masters")])
            )
            .sign(key, hashes.SHA256())
        )
        client_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)

        # create the CSR resource inside the cluster using kubectl
        csr_name = "wg-client"
        csr_yaml = dedent(
            f"""
            apiVersion: certificates.k8s.io/v1
            kind: CertificateSigningRequest
            metadata:
              name: {csr_name}
            spec:
              groups:
              - system:authenticated
              - system:masters
              request: {base64.b64encode(csr_pem).decode()}
              signerName: kubernetes.io/kube-apiserver-client
              usages:
              - client auth
            """
        )
        subprocess.run(
            [
                "docker",
                "exec",
                "-i",
                container_name,
                "sh",
                "-c",
                "kubectl apply -f -",
            ],
            input=csr_yaml.encode(),
            check=True,
        )
        subprocess.check_call(
            [
                "docker",
                "exec",
                container_name,
                "kubectl",
                "certificate",
                "approve",
                csr_name,
            ]
        )

        # after approving the CSR the certificate may take a moment to
        # appear in the resource status
        def fetch_cert() -> str:
            while True:
                cert = subprocess.check_output(
                    [
                        "docker",
                        "exec",
                        container_name,
                        "sh",
                        "-c",
                        (
                            f"kubectl get csr {csr_name} -o jsonpath='{{.status.certificate}}' "
                            "| base64 -d"
                        ),
                    ]
                ).decode()
                if cert:
                    return cert
                time.sleep(0.1)

        client_cert = ""
        _wait_timeout(
            fetch_cert,
            "k3s did not sign CSR",
            timeout=self.timeout,
        )

        client_cert = fetch_cert()

        logging.debug("retrieved signed client certificate from k3s")

        # the cert subject is "system:masters" so bind that user.
        subprocess.check_call(
            [
                "docker",
                "exec",
                container_name,
                "kubectl",
                "create",
                "clusterrolebinding",
                "wg-cert-binding",
                "--clusterrole=cluster-admin",
                "--user=system:masters",
            ]
        )

        logging.debug(f"k3s {container_name} is up on port {port}")
        return K3sInstance(
            port=port,
            token=token,
            container_name=container_name,
            client_cert=client_cert,
            client_key=client_key,
        )

    def start_oidc_server(
        self,
        warpgate_http_port,
        extra_scopes=None,
        users_override=None,
        extra_identity_resources=None,
        redirect_uris=None,
        extra_clients=None,
    ):
        port = alloc_port()
        container_name = f"warpgate-e2e-oidc-mock-{uuid.uuid4()}"

        oidc_data_dir = self.ctx.tmpdir / f"oidc-{uuid.uuid4()}"
        oidc_data_dir.mkdir(parents=True)

        import json as _json

        allowed_scopes = [
            "openid",
            "profile",
            "email",
            "preferred_username",
        ]
        if extra_scopes:
            allowed_scopes.extend(extra_scopes)

        clients_config = [
            {
                "ClientId": "warpgate-test",
                "ClientSecrets": ["warpgate-test-secret"],
                "AllowedGrantTypes": ["authorization_code"],
                "AllowedScopes": allowed_scopes,
                "ClientClaimsPrefix": "",
                # Emit identity-resource claims (email, preferred_username,
                # warpgate_roles, ...) directly in the ID token in addition to
                # the userinfo endpoint.  This is required by the Kubernetes
                # OIDC-Bearer auth path, which validates a raw ID token and does
                # not call userinfo.  Harmless for the interactive flows that
                # also read claims from userinfo.
                "AlwaysIncludeUserClaimsInIdToken": True,
                "RedirectUris": redirect_uris or [
                    f"https://127.0.0.1:{warpgate_http_port}/@warpgate/api/sso/return"
                ],
            }
        ]

        if extra_clients:
            clients_config.extend(extra_clients)

        clients_config_path = oidc_data_dir / "clients-config.json"
        with open(clients_config_path, "w") as f:
            _json.dump(clients_config, f)

        server_options = _json.dumps(
            {
                "AccessTokenJwtType": "JWT",
                "IssuerUri": f"http://localhost:{port}",
                "Discovery": {"ShowKeySet": True},
                "Authentication": {
                    "CookieSameSiteMode": "Lax",
                    "CheckSessionCookieSameSiteMode": "Lax",
                },
            }
        )
        default_users = [
            {
                "SubjectId": "1",
                "Username": "User1",
                "Password": "pwd",
                "Claims": [
                    {
                        "Type": "name",
                        "Value": "Sam Tailor",
                        "ValueType": "string",
                    },
                    {
                        "Type": "email",
                        "Value": "sam.tailor@gmail.com",
                        "ValueType": "string",
                    },
                    {
                        "Type": "preferred_username",
                        "Value": "sam_tailor",
                        "ValueType": "string",
                    },
                ],
            }
        ]
        users_config = _json.dumps(
            users_override if users_override is not None else default_users
        )
        identity_resources_list = [
            {"Name": "preferred_username", "ClaimTypes": ["preferred_username"]},
        ]
        if extra_identity_resources:
            identity_resources_list.extend(extra_identity_resources)
        identity_resources = _json.dumps(identity_resources_list)

        self.start(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                container_name,
                "-p",
                f"{port}:8080",
                "-e",
                "ASPNETCORE_ENVIRONMENT=Development",
                "-e",
                f"SERVER_OPTIONS_INLINE={server_options}",
                "-e",
                'LOGIN_OPTIONS_INLINE={"AllowRememberLogin": true}',
                "-e",
                f"USERS_CONFIGURATION_INLINE={users_config}",
                "-e",
                f"IDENTITY_RESOURCES_INLINE={identity_resources}",
                "-e",
                "CLIENTS_CONFIGURATION_PATH=/tmp/config/clients-config.json",
                "-v",
                f"{oidc_data_dir}:/tmp/config:ro",
                "xdevsoftware/oidc-server-mock:1.2.6",
            ]
        )

        def wait_oidc():
            import urllib3

            urllib3.disable_warnings()
            while True:
                try:
                    r = requests.get(
                        f"http://localhost:{port}/.well-known/openid-configuration",
                        timeout=2,
                    )
                    if r.status_code == 200:
                        break
                except Exception:
                    pass
                time.sleep(0.5)

        _wait_timeout(wait_oidc, "OIDC mock is not ready", timeout=self.timeout * 3)
        logging.debug(f"OIDC mock {container_name} is up on port {port}")
        return port

    def start_vault(self, root_token=None, engine: str = "vault") -> VaultInstance:
        """Runs a dev-mode Vault or OpenBao server (KV v2 auto-mounted at `secret/`).

        `engine` picks the actual server implementation started in Docker: "vault" (the default)
        for `hashicorp/vault`, or "openbao" for `openbao/openbao` -- Vault's API-compatible,
        community-governed fork. Both env-var prefixes are set on the container regardless of
        engine since OpenBao's dev-mode entrypoint still recognises the legacy `VAULT_*` names
        inherited from the fork, alongside its own `BAO_*` ones.
        """
        assert engine in ("vault", "openbao"), f"unknown secret backend engine: {engine}"
        image = "hashicorp/vault" if engine == "vault" else "openbao/openbao"

        port = alloc_port()
        container_name = f"warpgate-e2e-{engine}-{uuid.uuid4()}"
        root_token = root_token or f"root-{uuid.uuid4()}"

        self.start(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                container_name,
                "--cap-add=IPC_LOCK",
                "-p",
                f"{port}:8200",
                "-e",
                f"VAULT_DEV_ROOT_TOKEN_ID={root_token}",
                "-e",
                f"BAO_DEV_ROOT_TOKEN_ID={root_token}",
                "-e",
                "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
                "-e",
                "BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
                image,
            ]
        )

        def wait_vault():
            while True:
                try:
                    r = requests.get(f"http://127.0.0.1:{port}/v1/sys/health", timeout=2)
                    # dev-mode: 200 means initialized, unsealed and active
                    if r.status_code == 200:
                        break
                except Exception:
                    pass
                time.sleep(0.5)

        _wait_timeout(wait_vault, f"{engine} is not ready", timeout=self.timeout * 3)
        logging.debug(f"{engine} {container_name} is up on port {port}")
        return VaultInstance(
            port=port, root_token=root_token, container_name=container_name, backend_type=engine
        )

    def start_wg(
        self,
        config_patch=None,
        args=None,
        share_with: Optional[WarpgateProcess] = None,
        stderr=None,
        stdout=None,
        http_port=None,
        database_url=None,
    ) -> WarpgateProcess:
        args = args or ["run", "--enable-admin-token"]

        if share_with:
            config_path = share_with.config_path
            ssh_port = share_with.ssh_port
            mysql_port = share_with.mysql_port
            postgres_port = share_with.postgres_port
            http_port = share_with.http_port
            kubernetes_port = share_with.kubernetes_port
            vnc_port = share_with.vnc_port
            rdp_port = share_with.rdp_port
        else:
            ssh_port = alloc_port()
            http_port = http_port or alloc_port()
            mysql_port = alloc_port()
            postgres_port = alloc_port()
            kubernetes_port = alloc_port()
            vnc_port = alloc_port()
            rdp_port = alloc_port()

            data_dir = self.ctx.tmpdir / f"wg-data-{uuid.uuid4()}"
            data_dir.mkdir(parents=True)

            keys_dir = data_dir / "ssh-keys"
            keys_dir.mkdir(parents=True)
            for k in [
                Path("ssh-keys/wg/client-ed25519"),
                Path("ssh-keys/wg/client-rsa"),
                Path("ssh-keys/wg/host-ed25519"),
                Path("ssh-keys/wg/host-rsa"),
            ]:
                shutil.copy(k, keys_dir / k.name)

            for k in [
                Path("certs/tls.certificate.pem"),
                Path("certs/tls.key.pem"),
            ]:
                shutil.copy(k, data_dir / k.name)

            config_path = data_dir / "warpgate.yaml"

        def run(args, env={}):
            return self.start(
                [
                    os.path.join(cargo_root, binary_path),
                    "--config",
                    str(config_path),
                    *args,
                ],
                cwd=cargo_root,
                env={
                    **os.environ,
                    "LLVM_PROFILE_FILE": f"{cargo_root}/target/llvm-cov-target/warpgate-%m.profraw",
                    "WARPGATE_ADMIN_TOKEN": "token-value",
                    "WARPGATE_UNDER_TEST": "1",
                    "RUST_LOG": "debug",
                    **env,
                },
                stop_signal=signal.SIGINT,
                stop_timeout=5,
                stderr=stderr,
                stdout=stdout,
            )

        if not share_with:
            setup_args = [
                "unattended-setup",
                "--ssh-port",
                str(ssh_port),
                "--http-port",
                str(http_port),
                "--mysql-port",
                str(mysql_port),
                "--postgres-port",
                str(postgres_port),
                "--kubernetes-port",
                str(kubernetes_port),
                "--data-path",
                data_dir,
                "--external-host",
                "external-host",
            ]
            if database_url:
                setup_args += ["--database-url", database_url]
            p = run(
                setup_args,
                env={"WARPGATE_ADMIN_PASSWORD": "123"},
            )
            p.communicate()

            assert p.returncode == 0

            import yaml

            config = yaml.safe_load(config_path.open())
            config["ssh"]["host_key_verification"] = "auto_accept"
            # unattended-setup has no --vnc-port, so enable the VNC listener here,
            # reusing the TLS cert/key already copied into the data dir (for VeNCrypt).
            config["vnc"] = {
                "enable": True,
                "listen": f"0.0.0.0:{vnc_port}",
                "certificate": "tls.certificate.pem",
                "key": "tls.key.pem",
            }
            # Likewise no --rdp-port in unattended-setup; the RDP serve helper
            # terminates TLS itself, so hand it the same cert/key.
            config["rdp"] = {
                "enable": True,
                "listen": f"0.0.0.0:{rdp_port}",
                "certificate": "tls.certificate.pem",
                "key": "tls.key.pem",
            }
            # Record all sessions so tests can assert on recordings (unattended-setup
            # already picked a path under the data dir; just turn it on).
            config.setdefault("recordings", {})["enable"] = True
            if config_patch:
                always_merger.merge(config, config_patch)
            with config_path.open("w") as f:
                yaml.safe_dump(config, f)

        p = run(args)
        return WarpgateProcess(
            process=p,
            config_path=config_path,
            ssh_port=ssh_port,
            http_port=http_port,
            mysql_port=mysql_port,
            postgres_port=postgres_port,
            kubernetes_port=kubernetes_port,
            vnc_port=vnc_port,
            rdp_port=rdp_port,
        )

    def start_ssh_client(self, *args, password=None, **kwargs):
        preargs = []
        if password:
            preargs = ["sshpass", "-p", password]
        p = self.start(
            [
                *preargs,
                "ssh",
                # '-v',
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeychecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                *args,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            **kwargs,
        )
        return p

    def start(self, args, stop_timeout=3, stop_signal=signal.SIGTERM, **kwargs):
        p = subprocess.Popen(args, **kwargs)
        self.children.append(
            Child(process=p, stop_signal=stop_signal, stop_timeout=stop_timeout)
        )
        return p


@pytest.fixture(scope="session")
def timeout():
    t = os.getenv("TIMEOUT", "10")
    return int(t)


@pytest.fixture(scope="session")
def ctx():
    with tempfile.TemporaryDirectory() as tmpdir:
        ctx = Context(tmpdir=Path(tmpdir))
        yield ctx


@pytest.fixture(scope="session")
def processes(ctx, timeout, report_generation):
    mgr = ProcessManager(ctx, timeout)
    try:
        yield mgr
    finally:
        mgr.stop()


@pytest.fixture(scope="session", autouse=True)
def report_generation():
    if not enable_coverage:
        yield None
        return
    # subprocess.call(['cargo', 'llvm-cov', 'clean', '--workspace'])
    subprocess.check_call(
        [
            "cargo",
            "llvm-cov",
            "run",
            "--no-cfg-coverage-nightly",
            "--all-features",
            "--no-report",
            "--",
            "version",
        ],
        cwd=cargo_root,
    )
    yield
    # subprocess.check_call(['cargo', 'llvm-cov', '--no-run', '--hide-instantiations', '--html'], cwd=cargo_root)


@pytest.fixture(scope="session")
def shared_wg(processes: ProcessManager):
    wg = processes.start_wg()
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    wait_port(wg.ssh_port, for_process=wg.process)
    wait_port(wg.kubernetes_port, for_process=wg.process, recv=False)
    yield wg


# sometimes tests just want a pre‑configured API client for the admin
# endpoint.  previously everyone called ``admin_client(url)`` directly;
# a fixture lets us compute the URL from ``shared_wg`` once and removes
# boilerplate from individual tests.
from .api_client import admin_client as _admin_client_context  # noqa: E402


@pytest.fixture
def admin_client(shared_wg: WarpgateProcess):
    """Yields a ``sdk.DefaultApi`` instance authenticated with the
    built-in token and pointing at the running warpgate instance.

    Usage::

        def test_something(shared_wg, admin_client):
            user = admin_client.create_user(...)
    """
    url = f"https://localhost:{shared_wg.http_port}"
    with _admin_client_context(url) as api:
        yield api


# ----


@pytest.fixture(scope="session")
def shared_ssh_port(processes, wg_c_ed25519_pubkey):
    """Shared SSH server for tests that don't need their own instance.

    Used by test_role_expiry to avoid starting separate Docker containers.
    """
    port = processes.start_ssh_server(trusted_keys=[wg_c_ed25519_pubkey.read_text()])
    wait_port(port)
    return port


@pytest.fixture(scope="session")
def wg_c_ed25519_pubkey():
    return Path(os.getcwd()) / "ssh-keys/wg/client-ed25519.pub"


@pytest.fixture(scope="session")
def wg_c_rsa_pubkey():
    return Path(os.getcwd()) / "ssh-keys/wg/client-rsa.pub"


@pytest.fixture(scope="session")
def otp_key_base64():
    return "Isj0ekwF1YsKW8VUUQiU4awp/9dMnyMcTPH9rlr1OsE="


@pytest.fixture(scope="session")
def otp_key_base32():
    return "ELEPI6SMAXKYWCS3YVKFCCEU4GWCT76XJSPSGHCM6H624WXVHLAQ"


@pytest.fixture(scope="session")
def password_123_hash():
    return "$argon2id$v=19$m=4096,t=3,p=1$cxT6YKZS7r3uBT4nPJXEJQ$GhjTXyGi5vD2H/0X8D3VgJCZSXM4I8GiXRzl4k5ytk0"


def rdp_session_authorized(api, username):
    """Whether Warpgate has an authorized session for `username`.

    Warpgate stamps a session's username only on successful authorization, so this is a
    direct, client-independent read of the RDP auth verdict (the native RDP client can't
    observe a post-handshake rejection — see `rdp_client`).
    """
    return len(api.get_sessions(username=username).items) > 0


def wait_rdp_session_authorized(api, username, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if rdp_session_authorized(api, username):
            return True
        time.sleep(0.2)
    return False


logging.basicConfig(level=logging.DEBUG)
requests.packages.urllib3.disable_warnings()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
subprocess.call("chmod 600 ssh-keys/id*", shell=True)
