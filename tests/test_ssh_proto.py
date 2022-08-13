import subprocess
import tempfile
import pytest
from textwrap import dedent

from .conftest import ProcessManager
from .util import wait_port, alloc_port


@pytest.fixture(scope='class')
def ssh_port(processes, wg_c_ed25519_pubkey):
    yield processes.start_ssh_server(trusted_keys=[wg_c_ed25519_pubkey.read_text()])


@pytest.fixture(scope='class')
def wg_port(processes, ssh_port, password_123_hash):
    _, wg_ports = processes.start_wg(
        dedent(
            f'''\
            targets:
            -   name: ssh
                allow_roles: [role]
                ssh:
                    host: localhost
                    port: {ssh_port}
            -   name: ssh-bad-domain
                allow_roles: [role]
                ssh:
                    host: baddomainsomething
            users:
            -   username: user
                roles: [role]
                credentials:
                -   type: password
                    hash: '{password_123_hash}'
                -   type: publickey
                    key: {open('ssh-keys/id_rsa.pub').read().strip()}
            '''
        ),
    )
    wait_port(ssh_port)
    wait_port(wg_ports['ssh'])
    yield wg_ports['ssh']


common_args = [
    'user:ssh@localhost',
    '-i',
    '/dev/null',
    '-o',
    'PreferredAuthentications=password',
]


class Test:
    def test_stdout_stderr(
        self,
        processes: ProcessManager,
        wg_port,
    ):
        ssh_client = processes.start_ssh_client(
            '-p',
            str(wg_port),
            *common_args,
            'sh',
            '-c',
            '"echo -n stdout; echo -n stderr >&2"',
            password='123',
            stderr=subprocess.PIPE,
        )

        stdout, stderr = ssh_client.communicate()
        assert b'stdout' == stdout
        assert stderr.endswith(b'stderr')

    def test_pty(
        self,
        processes: ProcessManager,
        wg_port,
    ):
        ssh_client = processes.start_ssh_client(
            '-p',
            str(wg_port),
            '-tt',
            *common_args,
            'echo',
            'hello',
            password='123',
        )

        output = ssh_client.communicate()[0]
        assert b'Warpgate' in output
        assert b'Selected target:' in output
        assert b'hello\r\n' in output

    def test_signals(
        self,
        processes: ProcessManager,
        wg_port,
    ):
        ssh_client = processes.start_ssh_client(
            '-p',
            str(wg_port),
            '-v',
            *common_args,
            'sh', '-c',
            '"pkill -9 sh"',
            password='123',
        )

        assert ssh_client.returncode != 0

    def test_direct_tcpip(
        self,
        processes: ProcessManager,
        wg_port,
    ):
        local_port = alloc_port()
        ssh_client = processes.start_ssh_client(
            '-p',
            str(wg_port),
            '-v',
            *common_args,
            '-L', f'{local_port}:localhost:22',
            'sleep', '15',
            password='123',
        )

        data = wait_port(local_port)
        assert b'SSH-2.0' in data
        ssh_client.kill()

    def test_shell(
        self,
        processes: ProcessManager,
        wg_port,
    ):
        script = dedent(
            f'''
            set timeout 10

            spawn ssh -tt user:ssh@localhost -p {wg_port} -o StrictHostKeychecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password

            expect "password:"
            sleep 0.5
            send "123\\r"

            expect "#"
            sleep 0.5
            send "ls /bin/sh\\r"
            send "exit\\r"

            expect {{
                "/bin/sh"  {{ exit 0; }}
                eof {{ exit 1; }}
            }}

            exit 1
            '''
        )

        ssh_client = processes.start(
            ['expect', '-d'], stdin=subprocess.PIPE, stdout=subprocess.PIPE
        )

        output = ssh_client.communicate(script.encode())[0]
        assert ssh_client.returncode == 0, output

    def test_connection_error(
        self,
        processes: ProcessManager,
        wg_port,
    ):
        ssh_client = processes.start_ssh_client(
            '-p',
            str(wg_port),
            '-tt',
            'user:ssh-bad-domain@localhost',
            '-i',
            '/dev/null',
            '-o',
            'PreferredAuthentications=password',
            'echo',
            'hello',
            password='123',
            stderr=subprocess.PIPE,
        )

        stdout = ssh_client.communicate()[0]
        assert b'Selected target: ssh-bad-domain' in stdout
        assert ssh_client.returncode != 0

    def test_sftp(
        self,
        wg_port,
    ):
        with tempfile.TemporaryDirectory() as f:
            subprocess.check_call(
                [
                    'sftp',
                    '-P',
                    str(wg_port),
                    '-o',
                    'User=user:ssh',
                    '-o',
                    'IdentitiesOnly=yes',
                    '-o',
                    'IdentityFile=ssh-keys/id_rsa',
                    '-o',
                    'PreferredAuthentications=publickey',
                    '-o',
                    'StrictHostKeychecking=no',
                    '-o',
                    'UserKnownHostsFile=/dev/null',
                    'localhost:/etc/passwd',
                    f,
                ],
                stdout=subprocess.PIPE,
            )

            assert 'root:x:0:0:root' in open(f + '/passwd').read()
