import os
import psutil
import pytest
import shutil
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent
from typing import List

from .util import alloc_port


cargo_root = Path(os.getcwd()).parent


@dataclass
class Context:
    tmpdir: Path


class ProcessManager:
    children: List[subprocess.Popen]

    def __init__(self, ctx: Context) -> None:
        self.children = []
        self.ctx = ctx

    def stop(self):
        for child in self.children:
            try:
                p = psutil.Process(child.pid)
            except psutil.NoSuchProcess:
                continue

            p.send_signal(signal.SIGINT)

            for sp in p.children(recursive=True):
                try:
                    sp.terminate()
                except psutil.NoSuchProcess:
                    pass

            p.terminate()

            try:
                p.wait(timeout=3)
            except psutil.TimeoutExpired:
                for sp in p.children(recursive=True):
                    try:
                        sp.kill()
                    except psutil.NoSuchProcess:
                        pass

    def start_ssh_server(self, trusted_keys=[]):
        port = alloc_port()
        data_dir = self.ctx.tmpdir / 'sshd'
        data_dir.mkdir(parents=True)
        authorized_keys_path = data_dir / 'authorized_keys'
        authorized_keys_path.write_text('\n'.join(trusted_keys))
        config_path = data_dir / 'sshd_config'
        config_path.write_text(
            dedent(
                f'''\
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
                '''
            )
        )
        data_dir.chmod(0o700)
        authorized_keys_path.chmod(0o600)
        config_path.chmod(0o600)

        p = subprocess.Popen(
            [
                'docker',
                'run',
                '--rm',
                '-p',
                f'{port}:22',
                '-v',
                f'{data_dir}:{data_dir}',
                '-v',
                f'{os.getcwd()}/ssh-keys:/ssh-keys',
                'warpgate-e2e-ssh-server',
                '-f',
                str(config_path),
            ]
        )
        self.children.append(p)
        return port

    def start_wg(self, config='', args=None):
        port = alloc_port()
        data_dir = self.ctx.tmpdir / 'wg-data'
        data_dir.mkdir(parents=True)
        keys_dir = data_dir / 'keys'
        keys_dir.mkdir(parents=True)
        for k in [
            Path('ssh-keys/wg/client-ed25519'),
            Path('ssh-keys/wg/client-rsa'),
            Path('ssh-keys/wg/host-ed25519'),
            Path('ssh-keys/wg/host-rsa'),
        ]:
            shutil.copy(k, keys_dir / k.name)
        config_path = data_dir / 'warpgate.yaml'
        config_path.write_text(
            dedent(
                f'''\
                ssh:
                    enable: true
                    listen: 0.0.0.0:{port}
                    keys: {keys_dir}
                    host_key_verification: auto_accept
                http:
                    enable: false
                mysql:
                    enable: false
                recordings:
                    enable: false
                roles:
                - name: role
                http:
                    enable: false
                '''
            ) + config
        )
        args = args or ['run']
        p = subprocess.Popen(
            [
                f'{cargo_root}/target/llvm-cov-target/debug/warpgate',
                '--config',
                str(config_path),
                *args,
            ],
            cwd=cargo_root,
            env={
                **os.environ,
                'LLVM_PROFILE_FILE': f'{cargo_root}/target/llvm-cov-target/warpgate-%m.profraw',
            },
        )
        self.children.append(p)
        return p, port

    def start_ssh_client(self, *args, password=None):
        preargs = []
        if password:
            preargs = ['sshpass', '-p', password]
        p = subprocess.Popen(
            [
                *preargs,
                'ssh',
                # '-v',
                '-o',
                'StrictHostKeychecking=no',
                '-o',
                'UserKnownHostsFile=/dev/null',
                *args,
            ],
            stdout=subprocess.PIPE,
        )
        self.children.append(p)
        return p


@pytest.fixture
def ctx():
    with tempfile.TemporaryDirectory() as tmpdir:
        ctx = Context(tmpdir=Path(tmpdir))
        yield ctx


@pytest.fixture()
def processes(ctx):
    mgr = ProcessManager(ctx)
    try:
        yield mgr
    finally:
        mgr.stop()


@pytest.fixture(scope='session', autouse=True)
def report():
    subprocess.check_call(['cargo', 'llvm-cov', 'run', '--no-report', '--', '--version'], cwd=cargo_root)
    yield
    subprocess.check_call(['cargo', 'llvm-cov', '--no-run', '--hide-instantiations', '--html'], cwd=cargo_root)


# ----


@pytest.fixture
def wg_c_ed25519_pubkey():
    return Path(os.getcwd()) / 'ssh-keys/wg/client-ed25519.pub'
