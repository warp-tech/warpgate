import logging
import os
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent
from typing import List

children: List[subprocess.Popen] = []

last_port = 1234

cargo_root = Path(os.getcwd()).parent


@dataclass
class Context:
    tmpdir: Path


def alloc_port():
    global last_port
    last_port += 1
    return last_port


def wait_port(port):
    logging.debug(f'Waiting for port {port}')
    while True:
        try:
            s = socket.create_connection(('localhost', port))
            s.close()
            logging.debug(f'Port {port} is up')
            break
        except socket.error:
            time.sleep(0.1)
            continue


def start_ssh_server(ctx: Context, trusted_keys=[]):
    port = alloc_port()
    data_dir = ctx.tmpdir / 'sshd'
    data_dir.mkdir(parents=True)
    authorized_keys_path = data_dir / 'authorized_keys'
    authorized_keys_path.write_text('\n'.join(trusted_keys))
    config_path = data_dir / 'sshd_config'
    config_path.write_text(
        dedent(
            f'''\
            Port {port}
            AuthorizedKeysFile {authorized_keys_path}
            AllowAgentForwarding yes
            AllowTcpForwarding yes
            GatewayPorts yes
            X11Forwarding yes
            UseDNS no
            PermitTunnel yes
            StrictModes no
            UsePam no
            HostKey {os.getcwd()}/ssh-keys/id_ed25519
            Subsystem	sftp	/usr/lib/ssh/sftp-server
            '''
        )
    )
    data_dir.chmod(0o700)
    authorized_keys_path.chmod(0o600)
    config_path.chmod(0o600)

    p = subprocess.Popen(['/usr/sbin/sshd', '-f', str(config_path), '-De'])
    children.append(p)
    return port


def start_wg(ctx: Context, config=''):
    port = alloc_port()
    data_dir = ctx.tmpdir / 'wg-data'
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
        )
        + config
    )
    p = subprocess.Popen(
        [
            'cargo',
            'llvm-cov',
            'run',
            '--no-report',
            '--',
            '--config',
            str(config_path),
            'run',
        ],
        cwd=cargo_root,
    )
    children.append(p)
    return port


def start_ssh_client(*args, password=None):
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
    )
    children.append(p)
    return p


logging.basicConfig(level=logging.DEBUG)
wg_c_ed25519_pubkey = Path(os.getcwd()) / 'ssh-keys/wg/client-ed25519.pub'


class TestClass:
    def test_ssh_password_auth(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(tmpdir=Path(tmpdir))
            print(f'Working in {ctx.tmpdir}')
            try:
                ssh_port = start_ssh_server(ctx, trusted_keys=[wg_c_ed25519_pubkey.read_text()])
                wait_port(ssh_port)
                wg_port = start_wg(
                    ctx,
                    dedent(
                        f'''\
                        targets:
                        -   name: ssh
                            allow_roles: [role]
                            ssh:
                                host: localhost
                                port: {ssh_port}
                                username: {os.getlogin()}
                        users:
                        -   username: user
                            roles: [role]
                            credentials:
                            -   type: password
                                hash: '$argon2id$v=19$m=4096,t=3,p=1$cxT6YKZS7r3uBT4nPJXEJQ$GhjTXyGi5vD2H/0X8D3VgJCZSXM4I8GiXRzl4k5ytk0' # 123
                        '''
                    ),
                )
                wait_port(wg_port)
                logging.info('running')
                ssh_client = start_ssh_client(
                    'user:ssh@localhost',
                    '-p',
                    str(wg_port),
                    '-i',
                    '/dev/null',
                    '-o',
                    'PreferredAuthentications=password',
                    'ls',
                    password='123',
                )
                print(ssh_client.communicate())
                print(ssh_client.returncode)
                assert ssh_client.returncode == 0
            finally:
                for p in children:
                    p.terminate()
                for p in children:
                    p.kill()

        # cargo llvm-cov --no-run --open

TestClass().test_ssh_password_auth()
