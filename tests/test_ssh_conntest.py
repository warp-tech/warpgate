from pathlib import Path
from textwrap import dedent

from .conftest import ProcessManager
from .util import alloc_port, wait_port


class Test:
    def test_success(
        self, processes: ProcessManager, wg_c_ed25519_pubkey: Path, timeout
    ):
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)
        proc, _ = processes.start_wg(
            config=dedent(
                f'''\
                users: []
                targets:
                -   name: ssh
                    allow_roles: [role]
                    ssh:
                        host: localhost
                        port: {ssh_port}
                '''
            ),
            args=['test-target', 'ssh'],
        )
        proc.wait(timeout=timeout)
        assert proc.returncode == 0

    def test_fail(self, processes: ProcessManager, timeout):
        ssh_port = alloc_port()
        proc, _ = processes.start_wg(
            config=dedent(
                f'''\
                users: []
                targets:
                -   name: ssh
                    allow_roles: [role]
                    ssh:
                        host: localhost
                        port: {ssh_port}
                '''
            ),
            args=['test-target', 'ssh'],
        )
        proc.wait(timeout=timeout)
        assert proc.returncode != 0
