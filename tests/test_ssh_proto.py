import requests
import subprocess
import tempfile
import time
import pytest
from textwrap import dedent

from .conftest import ProcessManager
from .util import wait_port, alloc_port


@pytest.fixture(scope='class')
def ssh_port(processes, wg_c_ed25519_pubkey):
    yield processes.start_ssh_server(trusted_keys=[wg_c_ed25519_pubkey.read_text()])


@pytest.fixture(scope='class')
def wg_port(processes, ssh_port, password_123_hash):
    with processes.start_wg(
        dedent(
            f'''\
            targets:
            -   name: ssh
                allow_roles: [role]
                ssh:
                    host: 127.0.0.1
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
                    key: {open('ssh-keys/id_ed25519.pub').read().strip()}
            '''
        ),
    ) as (_, wg_ports):
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
        timeout,
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

        stdout, stderr = ssh_client.communicate(timeout=timeout)
        assert b'stdout' == stdout
        assert stderr.endswith(b'stderr')

    def test_pty(
        self,
        processes: ProcessManager,
        wg_port,
        timeout,
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

        output = ssh_client.communicate(timeout=timeout)[0]
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
        timeout,
    ):
        local_port = alloc_port()
        wait_port(wg_port)
        ssh_client = processes.start_ssh_client(
            '-p',
            str(wg_port),
            '-v',
            *common_args,
            '-L', f'{local_port}:neverssl.com:80',
            '-N',
            password='123',
        )

        time.sleep(10)

        wait_port(local_port, recv=False)

        s = requests.Session()
        retries = requests.adapters.Retry(total=5, backoff_factor=1)
        s.mount('http://', requests.adapters.HTTPAdapter(max_retries=retries))
        response = s.get(f'http://localhost:{local_port}', timeout=timeout)
        assert response.status_code == 200
        ssh_client.kill()

    def test_tcpip_forward(
        self,
        processes: ProcessManager,
        wg_port,
        timeout,
    ):
        wait_port(wg_port)
        pf_client = processes.start_ssh_client(
            '-p',
            str(wg_port),
            '-v',
            *common_args,
            '-R', '1234:neverssl.com:80',
            '-N',
            password='123',
        )
        time.sleep(5)
        ssh_client = processes.start_ssh_client(
            '-p',
            str(wg_port),
            '-v',
            *common_args,
            'curl', '-v', 'http://localhost:1234',
            password='123',
        )
        output = ssh_client.communicate(timeout=timeout)[0]
        print(output)
        assert ssh_client.returncode == 0
        assert b'<html>' in output
        pf_client.kill()

    def test_shell(
        self,
        processes: ProcessManager,
        wg_port,
        timeout,
    ):
        script = dedent(
            f'''
            set timeout {timeout - 5}

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

        output = ssh_client.communicate(script.encode(), timeout=timeout)[0]
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
            password='123',
        )

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
                    'IdentityFile=ssh-keys/id_ed25519',
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
