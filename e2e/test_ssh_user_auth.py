import logging
import os
import paramiko
from pathlib import Path
from textwrap import dedent

from .conftest import ProcessManager
from .util import wait_port


class TestSSHUserAuthClass:
    def test_ssh_password_auth(
        self, processes: ProcessManager, wg_c_ed25519_pubkey: Path
    ):
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)
        _, wg_port = processes.start_wg(
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

        ssh_client = processes.start_ssh_client(
            'user:ssh@localhost',
            '-p',
            str(wg_port),
            '-i',
            '/dev/null',
            '-o',
            'PreferredAuthentications=password',
            'ls',
            '/bin/sh',
            password='123',
        )
        assert ssh_client.communicate()[0] == b'/bin/sh\n'
        assert ssh_client.returncode == 0

        ssh_client = processes.start_ssh_client(
            'user:ssh@localhost',
            '-p',
            str(wg_port),
            '-i',
            '/dev/null',
            '-o',
            'PreferredAuthentications=password',
            'ls',
            '/bin/sh',
            password='321',
        )
        ssh_client.communicate()
        assert ssh_client.returncode != 0

    def test_ssh_user_ed25519_pubkey_auth(
        self, processes: ProcessManager, wg_c_ed25519_pubkey: Path
    ):
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        _, wg_port = processes.start_wg(
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
                    -   type: publickey
                        key: {open('ssh-keys/id_ed25519.pub').read().strip()}
                '''
            ),
        )
        wait_port(wg_port)

        ssh_client = processes.start_ssh_client(
            'user:ssh@localhost',
            '-p',
            str(wg_port),
            '-i',
            'ssh-keys/id_ed25519',
            '-o',
            'PreferredAuthentications=publickey',
            'ls',
            '/bin/sh',
        )
        assert ssh_client.communicate()[0] == b'/bin/sh\n'
        assert ssh_client.returncode == 0

        ssh_client = processes.start_ssh_client(
            'user:ssh@localhost',
            '-p',
            str(wg_port),
            '-i',
            'ssh-keys/id_rsa',
            '-o',
            'PreferredAuthentications=publickey',
            'ls',
            '/bin/sh',
        )
        assert ssh_client.communicate()[0] == b''
        assert ssh_client.returncode != 0

    def test_ssh_user_rsa_pubkey_auth(
        self, processes: ProcessManager, wg_c_ed25519_pubkey: Path
    ):
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)
        _, wg_port = processes.start_wg(
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
                    -   type: publickey
                        key: {open('ssh-keys/id_rsa.pub').read().strip()}
                '''
            ),
        )
        wait_port(wg_port)
        logging.info('running')

        ssh_client = processes.start_ssh_client(
            'user:ssh@localhost',
            '-p',
            str(wg_port),
            '-i',
            'ssh-keys/id_rsa',
            '-o',
            'PreferredAuthentications=publickey',
            'ls',
            '/bin/sh',
        )
        assert ssh_client.communicate()[0] == b'/bin/sh\n'
        assert ssh_client.returncode == 0

        ssh_client = processes.start_ssh_client(
            'user:ssh@localhost',
            '-p',
            str(wg_port),
            '-i',
            'ssh-keys/id_ed25519',
            '-o',
            'PreferredAuthentications=publickey',
            'ls',
            '/bin/sh',
        )
        assert ssh_client.communicate()[0] == b''
        assert ssh_client.returncode != 0
