from asyncio import subprocess
import os
import pyotp
from pathlib import Path
from textwrap import dedent

from .conftest import ProcessManager
from .util import wait_port


class Test:
    def test_otp(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        otp_key_base32: str,
        otp_key_base64: str,
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
                        username: {os.getlogin()}
                users:
                -   username: user
                    roles: [role]
                    credentials:
                    -   type: publickey
                        key: {open('ssh-keys/id_ed25519.pub').read().strip()}
                    -   type: otp
                        key: {otp_key_base64}
                    require:
                        ssh: [publickey, otp]
                '''
            ),
        )

        wait_port(ssh_port)
        wait_port([wg_ports['ssh']])

        totp = pyotp.TOTP(otp_key_base32)

        script = dedent(
            f'''
            set timeout 10

            spawn ssh user:ssh@localhost -p {[wg_ports['ssh']]} -o StrictHostKeychecking=no -o UserKnownHostsFile=/dev/null  -o IdentitiesOnly=yes -o IdentityFile=ssh-keys/id_ed25519 -o PreferredAuthentications=publickey,keyboard-interactive ls /bin/sh

            expect "Two-factor authentication"
            sleep 0.5
            send "{totp.now()}\\r"

            expect {{
                "/bin/sh"  {{ exit 0; }}
                eof {{ exit 1; }}
            }}
            '''
        )

        ssh_client = processes.start(
            ['expect'], stdin=subprocess.PIPE, stdout=subprocess.PIPE
        )

        output = ssh_client.communicate(script.encode())[0]
        assert ssh_client.returncode == 0, output

        script = dedent(
            f'''
            set timeout 10

            spawn ssh user:ssh@localhost -p {[wg_ports['ssh']]} -o StrictHostKeychecking=no -o UserKnownHostsFile=/dev/null  -o IdentitiesOnly=yes -o IdentityFile=ssh-keys/id_ed25519 -o PreferredAuthentications=publickey,keyboard-interactive ls /bin/sh

            expect "Two-factor authentication"
            sleep 0.5
            send "12345678\\r"

            expect {{
                "/bin/sh"  {{ exit 0; }}
                "Two-factor authentication" {{ exit 1; }}
                eof {{ exit 1; }}
            }}
            '''
        )

        ssh_client = processes.start(
            ['expect'], stdin=subprocess.PIPE, stdout=subprocess.PIPE
        )

        output = ssh_client.communicate(script.encode())[0]
        assert ssh_client.returncode != 0, output
