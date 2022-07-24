from dataclasses import dataclass
import logging
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
from textwrap import dedent
import time
from typing import List

children: List[subprocess.Popen] = []

last_port = 1234


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


def start_wg(ctx: Context, config='', ssh_keys=[]):
    port = alloc_port()
    data_dir = ctx.tmpdir / 'wg-data'
    data_dir.mkdir(parents=True)
    keys_dir = data_dir / 'keys'
    keys_dir.mkdir(parents=True)
    for k in ssh_keys:
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
        users:
          - username: user
            roles: [role]
            credentials:
            - type: password
              hash: '$argon2id$v=19$m=4096,t=3,p=1$cxT6YKZS7r3uBT4nPJXEJQ$GhjTXyGi5vD2H/0X8D3VgJCZSXM4I8GiXRzl4k5ytk0' # 123
        http:
            enable: false
    '''
        )
        + config
    )
    p = subprocess.Popen(
        [
            'cargo',
            'run',
            '--',
            '--config',
            str(config_path),
            'run',
        ],
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

with tempfile.TemporaryDirectory() as tmpdir:
    wg_c_ed25519_pubkey = Path(os.getcwd()) / 'ssh-keys/client-ed25519.pub'
    ctx = Context(tmpdir=Path(tmpdir))
    print(f'Working in {ctx.tmpdir}')
    try:
        ssh_port = start_ssh_server(
            ctx, trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)
        wg_port = start_wg(
            ctx,
            dedent(
                f'''\
                targets:
                - name: ssh
                  allow_roles: [role]
                  ssh:
                    host: localhost
                    port: {ssh_port}
                    username: {os.getlogin()}
                '''
            ),
            ssh_keys=[
                Path('ssh-keys/client-ed25519'),
                Path('ssh-keys/client-rsa'),
                Path('ssh-keys/host-ed25519'),
                Path('ssh-keys/host-rsa'),
            ],
        )
        wait_port(wg_port)
        logging.info('running')
        ssh_client = start_ssh_client(
            'user:ssh@localhost', '-p', str(wg_port), '-i', '/dev/null', '-o', 'PreferredAuthentications=password', 'ls', password='123'
        )
        ssh_client.communicate()
    finally:
        for p in children:
            p.terminate()
