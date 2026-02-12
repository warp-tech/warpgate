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
from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent
from typing import List, Optional

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
class Child:
    process: subprocess.Popen
    stop_signal: signal.Signals
    stop_timeout: float


@dataclass
class WarpgateProcess:
    config_path: Path
    process: subprocess.Popen
    http_port: int
    ssh_port: int
    mysql_port: int
    postgres_port: int
    kubernetes_port: int


class ProcessManager:
    children: List[Child]

    def __init__(self, ctx: Context, timeout: int) -> None:
        self.children = []
        self.ctx = ctx
        self.timeout = timeout

    def stop(self):
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

    def start_ssh_server(self, trusted_keys=[], extra_config=""):
        port = alloc_port()
        data_dir = self.ctx.tmpdir / f"sshd-{uuid.uuid4()}"
        data_dir.mkdir(parents=True)
        authorized_keys_path = data_dir / "authorized_keys"
        authorized_keys_path.write_text("\n".join(trusted_keys))
        config_path = data_dir / "sshd_config"
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

        self.start(
            [
                "docker",
                "run",
                "--rm",
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
        return port

    def start_mysql_server(self):
        port = alloc_port()
        self.start(
            ["docker", "run", "--rm", "-p", f"{port}:3306", "warpgate-e2e-mysql-server"]
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

    def start_k3s(self):
        """Start a k3s server in Docker and return (port, token, container_name).

        This will run a privileged k3s container, wait for the API to be ready,
        create a ServiceAccount, and obtain a bearer token for it.
        """
        port = alloc_port()
        container_name = f"warpgate-e2e-k3s-{uuid.uuid4()}"
        image = os.getenv("K3S_IMAGE", "rancher/k3s:v1.27.4-k3s1")

        # Start container (runs in foreground so we can stop it via ProcessManager.stop)
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
            ]
        )

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

        # Create service account
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

        # Assign cluster admin role
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

        print(token)

        logging.debug(f"k3s {container_name} is up on port {port}")
        return {"port": port, "token": token, "container_name": container_name}

    def start_wg(
        self,
        config="",
        args=None,
        share_with: Optional[WarpgateProcess] = None,
        stderr=None,
        stdout=None,
    ) -> WarpgateProcess:
        args = args or ["run", "--enable-admin-token"]

        if share_with:
            config_path = share_with.config_path
            ssh_port = share_with.ssh_port
            mysql_port = share_with.mysql_port
            postgres_port = share_with.postgres_port
            http_port = share_with.http_port
        else:
            ssh_port = alloc_port()
            http_port = alloc_port()
            mysql_port = alloc_port()
            postgres_port = alloc_port()
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
                    **env,
                },
                stop_signal=signal.SIGINT,
                stop_timeout=5,
                stderr=stderr,
                stdout=stdout,
            )

        if not share_with:
            kubernetes_port = alloc_port()
            p = run(
                [
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
                ],
                env={"WARPGATE_ADMIN_PASSWORD": "123"},
            )
            p.communicate()

            assert p.returncode == 0

            import yaml

            config = yaml.safe_load(config_path.open())
            config["ssh"]["host_key_verification"] = "auto_accept"
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
            kubernetes_port=kubernetes_port
            if not share_with
            else (
                share_with.kubernetes_port
                if hasattr(share_with, "kubernetes_port")
                else None
            ),
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
    # Wait for Kubernetes listen port if configured
    if getattr(wg, "kubernetes_port", None):
        wait_port(wg.kubernetes_port, for_process=wg.process, recv=False)
    yield wg


# ----


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


logging.basicConfig(level=logging.DEBUG)
requests.packages.urllib3.disable_warnings()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
subprocess.call("chmod 600 ssh-keys/id*", shell=True)
