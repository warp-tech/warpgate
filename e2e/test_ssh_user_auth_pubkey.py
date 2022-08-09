from pathlib import Path
from textwrap import dedent

from .conftest import ProcessManager
from .util import wait_port


class Test:
    def test_ed25519(
        self, processes: ProcessManager, wg_c_ed25519_pubkey: Path, username
    ):
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )

        _, wg_ports = processes.start_wg(
            dedent(
                f'''\
                targets:
                -   name: ssh
                    allow_roles: [role]
                    ssh:
                        host: localhost
                        port: {ssh_port}
                        username: {username}
                users:
                -   username: user
                    roles: [role]
                    credentials:
                    -   type: publickey
                        key: {open('ssh-keys/id_ed25519.pub').read().strip()}
                '''
            ),
        )

        wait_port(ssh_port)
        wait_port(wg_ports['ssh'])

        ssh_client = processes.start_ssh_client(
            'user:ssh@localhost',
            '-p',
            str(wg_ports['ssh']),
            '-o',
            'IdentityFile=ssh-keys/id_ed25519',
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
            str(wg_ports['ssh']),
            '-o',
            'IdentityFile=ssh-keys/id_rsa',
            '-o',
            'PreferredAuthentications=publickey',
            'ls',
            '/bin/sh',
        )
        assert ssh_client.communicate()[0] == b''
        assert ssh_client.returncode != 0

    def test_rsa(self, processes: ProcessManager, wg_c_ed25519_pubkey: Path, username):
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )

        _, wg_ports = processes.start_wg(
            dedent(
                f'''\
                targets:
                -   name: ssh
                    allow_roles: [role]
                    ssh:
                        host: localhost
                        port: {ssh_port}
                        username: {username}
                users:
                -   username: user
                    roles: [role]
                    credentials:
                    -   type: publickey
                        key: {open('ssh-keys/id_rsa.pub').read().strip()}
                '''
            ),
        )

        wait_port(ssh_port)
        wait_port(wg_ports['ssh'])

        ssh_client = processes.start_ssh_client(
            'user:ssh@localhost',
            '-p',
            str(wg_ports['ssh']),
            '-o',
            'IdentityFile=ssh-keys/id_rsa',
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
            str(wg_ports['ssh']),
            '-o',
            'IdentityFile=ssh-keys/id_ed25519',
            '-o',
            'PreferredAuthentications=publickey',
            'ls',
            '/bin/sh',
        )
        assert ssh_client.communicate()[0] == b''
        assert ssh_client.returncode != 0
