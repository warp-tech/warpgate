import os
from pathlib import Path
from textwrap import dedent

from .conftest import ProcessManager
from .util import wait_port


class Test:
    def test_bad_target(
        self, processes: ProcessManager, wg_c_ed25519_pubkey: Path
    ):
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )

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

        wait_port(ssh_port)
        wait_port(wg_port)

        ssh_client = processes.start_ssh_client(
            '-t',
            'user:badtarget@localhost',
            '-p',
            str(wg_port),
            '-i',
            '/dev/null',
            '-o',
            'PreferredAuthentications=password',
            'echo',
            'hello',
            password='123',
        )

        assert ssh_client.returncode != 0
