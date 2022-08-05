import logging
import os
import paramiko
import pyotp
from pathlib import Path
from textwrap import dedent

from .conftest import ProcessManager
from .util import wait_port


class TestSSHUserAuthClass:
    def test_ssh_user_otp_auth(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        otp_key_base32: str,
        otp_key_base64: str,
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
                    -   type: otp
                        key: {otp_key_base64}
                    require:
                        ssh: [publickey, otp]
                '''
            ),
        )
        wait_port(wg_port)
        logging.info('running')

        import socket
        from ssh2.session import Session

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', wg_port))
        s = Session()
        s.handshake(sock)
        try:
            s.userauth_publickey_fromfile('user:ssh', 'ssh-keys/id_ed25519')
        except BaseException as e:
            print(e)

        totp = pyotp.TOTP(otp_key_base32)
        s.userauth_keyboardinteractive('user:ssh', totp.now())

        chan = s.open_session()
        chan.execute('ls /bin/sh')
        chan.wait_eof()
        chan.wait_closed()

        assert chan.read()[1] == b'/bin/sh\n'
        assert chan.get_exit_status() == 0
