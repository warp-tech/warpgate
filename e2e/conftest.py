import os
import threading
import warnings
import psutil
import pytest
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
        ssh_port = alloc_port()
        http_port = alloc_port()
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
                recordings:
                    enable: false
                roles:
                - name: role
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
        return p, {
            'ssh': ssh_port,
            'http': http_port,
        }

    def start_ssh_client(self, *args, password=None, **kwargs):
        preargs = []
        if password:
            preargs = ['sshpass', '-p', password]
        p = subprocess.Popen(
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
        self.children.append(p)
        return p

    def start(self, args, **kwargs):
        p = subprocess.Popen(args, **kwargs)
        self.children.append(p)
        return p


@pytest.fixture(scope='session')
def ctx():
    with tempfile.TemporaryDirectory() as tmpdir:
        ctx = Context(tmpdir=Path(tmpdir))
        yield ctx


@pytest.fixture(scope='session')
def processes(ctx):
    mgr = ProcessManager(ctx)
    try:
        yield mgr
    finally:
        mgr.stop()


@pytest.fixture(scope='session', autouse=True)
def report():
    # subprocess.call(['cargo', 'llvm-cov', 'clean', '--workspace'])
    subprocess.check_call(['cargo', 'llvm-cov', 'run', '--no-report', '--', '--version'], cwd=cargo_root)
    yield
    subprocess.check_call(['cargo', 'llvm-cov', '--no-run', '--hide-instantiations', '--html'], cwd=cargo_root)


@pytest.fixture(scope='session')
def echo_server_port():
    from flask import Flask, request, jsonify
    app = Flask(__name__)

    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def echo(path):
        return jsonify({
            'method': request.method,
            'args': request.args,
            'path': request.path,
        })

    port = alloc_port()

    def runner():
        app.run(port=port)

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()

    yield port


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


subprocess.call('chmod 600 ssh-keys/id*', shell=True)
warnings.simplefilter('ignore', urllib3.exceptions.InsecureRequestWarning)
