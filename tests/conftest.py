import logging
import os
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
from typing import List

from .util import alloc_port
from .test_http_common import http_common_wg_port, echo_server_port  # noqa


cargo_root = Path(os.getcwd()).parent


@dataclass
class Context:
    tmpdir: Path


@dataclass
class Child:
    process: subprocess.Popen
    stop_signal: signal.Signals
    stop_timeout: float


class ProcessManager:
    children: List[Child]

    def __init__(self, ctx: Context) -> None:
        self.children = []
        self.ctx = ctx

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

    def start_ssh_server(self, trusted_keys=[]):
        port = alloc_port()
        data_dir = self.ctx.tmpdir / f'sshd-{uuid.uuid4()}'
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

        self.start(
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
        return port

    def start_mysql_server(self):
        port = alloc_port()
        self.start(
            [
                'docker',
                'run',
                '--rm',
                '-p',
                f'{port}:3306',
                'warpgate-e2e-mysql-server'
            ]
        )
        return port

    def start_wg(self, config='', args=None):
        ssh_port = alloc_port()
        http_port = alloc_port()
        mysql_port = alloc_port()
        data_dir = self.ctx.tmpdir / f'wg-data-{uuid.uuid4()}'
        data_dir.mkdir(parents=True)
        keys_dir = data_dir / 'keys'
        keys_dir.mkdir(parents=True)
        for k in [
            Path('ssh-keys/wg/client-ed25519'),
            Path('ssh-keys/wg/client-rsa'),
            Path('ssh-keys/wg/host-ed25519'),
            Path('ssh-keys/wg/host-rsa'),
            Path('certs/tls.certificate.pem'),
            Path('certs/tls.key.pem'),
        ]:
            shutil.copy(k, keys_dir / k.name)
        config_path = data_dir / 'warpgate.yaml'
        config_path.write_text(
            dedent(
                f'''\
                ssh:
                    enable: true
                    listen: 0.0.0.0:{ssh_port}
                    keys: {keys_dir}
                    host_key_verification: auto_accept
                http:
                    enable: true
                    listen: 0.0.0.0:{http_port}
                    certificate: {keys_dir}/tls.certificate.pem
                    key: {keys_dir}/tls.key.pem
                mysql:
                    enable: true
                    listen: 0.0.0.0:{mysql_port}
                    certificate: {keys_dir}/tls.certificate.pem
                    key: {keys_dir}/tls.key.pem
                recordings:
                    enable: false
                roles:
                - name: role
                - name: admin
                - name: warpgate:admin
                '''
            ) + config
        )
        args = args or ['run']
        p = self.start(
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
            stop_signal=signal.SIGINT,
            stop_timeout=5,
        )
        return p, {
            'ssh': ssh_port,
            'http': http_port,
            'mysql': mysql_port,
        }

    def start_ssh_client(self, *args, password=None, **kwargs):
        preargs = []
        if password:
            preargs = ['sshpass', '-p', password]
        p = self.start(
            [
                *preargs,
                'ssh',
                # '-v',
                '-o',
                'IdentitiesOnly=yes',
                '-o',
                'StrictHostKeychecking=no',
                '-o',
                'UserKnownHostsFile=/dev/null',
                *args,
            ],
            stdout=subprocess.PIPE,
            **kwargs,
        )
        return p

    def start(self, args, stop_timeout=3, stop_signal=signal.SIGTERM, **kwargs):
        p = subprocess.Popen(args, **kwargs)
        self.children.append(Child(process=p, stop_signal=stop_signal, stop_timeout=stop_timeout))
        return p


@pytest.fixture(scope='session')
def ctx():
    with tempfile.TemporaryDirectory() as tmpdir:
        ctx = Context(tmpdir=Path(tmpdir))
        yield ctx


@pytest.fixture(scope='session')
def processes(ctx, report_generation):
    mgr = ProcessManager(ctx)
    try:
        yield mgr
    finally:
        mgr.stop()


@pytest.fixture(scope='session', autouse=True)
def report_generation():
    # subprocess.call(['cargo', 'llvm-cov', 'clean', '--workspace'])
    subprocess.check_call(['cargo', 'llvm-cov', 'run', '--no-report', '--', '--version'], cwd=cargo_root)
    yield
    # subprocess.check_call(['cargo', 'llvm-cov', '--no-run', '--hide-instantiations', '--html'], cwd=cargo_root)


# ----


@pytest.fixture(scope='session')
def wg_c_ed25519_pubkey():
    return Path(os.getcwd()) / 'ssh-keys/wg/client-ed25519.pub'


@pytest.fixture(scope='session')
def otp_key_base64():
    return 'Isj0ekwF1YsKW8VUUQiU4awp/9dMnyMcTPH9rlr1OsE='


@pytest.fixture(scope='session')
def otp_key_base32():
    return 'ELEPI6SMAXKYWCS3YVKFCCEU4GWCT76XJSPSGHCM6H624WXVHLAQ'


@pytest.fixture(scope='session')
def password_123_hash():
    return '$argon2id$v=19$m=4096,t=3,p=1$cxT6YKZS7r3uBT4nPJXEJQ$GhjTXyGi5vD2H/0X8D3VgJCZSXM4I8GiXRzl4k5ytk0'


logging.basicConfig(level=logging.DEBUG)
requests.packages.urllib3.disable_warnings()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
subprocess.call('chmod 600 ssh-keys/id*', shell=True)
