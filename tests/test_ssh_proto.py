from base64 import b64decode
from uuid import uuid4
import requests
import subprocess
import tempfile
import time
import pytest
from textwrap import dedent

from tests.api_client import (
    api_add_role_to_target,
    api_add_role_to_user,
    api_admin_session,
    api_create_role,
    api_create_target,
    api_create_user,
)

from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port, alloc_port


@pytest.fixture(scope="session")
def ssh_port(processes, wg_c_ed25519_pubkey):
    yield processes.start_ssh_server(trusted_keys=[wg_c_ed25519_pubkey.read_text()])


@pytest.fixture(scope="session")
def setup_common_definitions(
    otp_key_base64,
    ssh_port,
):
    def inner(url):
        with api_admin_session(url) as session:
            role = api_create_role(url, session, {"name": f"role-{uuid4()}"})
            user = api_create_user(
                url,
                session,
                {
                    "username": "user",
                    "credentials": [
                        {
                            "kind": "Password",
                            "hash": "123",
                        },
                        {
                            "kind": "PublicKey",
                            "key": open("ssh-keys/id_ed25519.pub").read().strip(),
                        },
                    ],
                },
            )
            otpuser = api_create_user(
                url,
                session,
                {
                    "username": "userwithotp",
                    "credentials": [
                        {"kind": "Password", "hash": "123"},
                        {"kind": "Totp", "key": list(b64decode(otp_key_base64))},
                    ],
                    "credential_policy": {
                        "http": ["Password", "Totp"],
                    },
                },
            )
            api_add_role_to_user(url, session, user["id"], role["id"])
            api_add_role_to_user(url, session, otpuser["id"], role["id"])
            ssh_target = api_create_target(
                url,
                session,
                {
                    "name": "ssh",
                    "options": {
                        "kind": "Ssh",
                        "host": "localhost",
                        "port": ssh_port,
                        "username": "root",
                        "auth": {"kind": "PublicKey"},
                    },
                },
            )
            api_add_role_to_target(url, session, ssh_target["id"], role["id"])
            bad_target = api_create_target(
                url,
                session,
                {
                    "name": "ssh",
                    "options": {
                        "kind": "Ssh",
                        "host": "baddomainsomething",
                        "port": 22,
                        "username": "root",
                        "auth": {"kind": "PublicKey"},
                    },
                },
            )
            api_add_role_to_target(url, session, bad_target["id"], role["id"])

    return inner


@pytest.fixture(scope="session")
def wg_port(shared_wg: WarpgateProcess, setup_common_definitions):
    wait_port(shared_wg.ssh_port)
    setup_common_definitions(f'https://localhost:{shared_wg.http_port}')
    yield shared_wg.ssh_port


common_args = [
    "user:ssh@localhost",
    "-i",
    "/dev/null",
    "-o",
    "PreferredAuthentications=password",
]


class Test:
    def test_stdout_stderr(
        self,
        processes: ProcessManager,
        wg_port,
        timeout,
    ):
        ssh_client = processes.start_ssh_client(
            "-p",
            str(wg_port),
            *common_args,
            "sh",
            "-c",
            '"echo -n stdout; echo -n stderr >&2"',
            password="123",
            stderr=subprocess.PIPE,
        )

        stdout, stderr = ssh_client.communicate(timeout=timeout)
        assert b"stdout" == stdout
        assert stderr.endswith(b"stderr")

    def test_pty(
        self,
        processes: ProcessManager,
        wg_port,
        timeout,
    ):
        ssh_client = processes.start_ssh_client(
            "-p",
            str(wg_port),
            "-tt",
            *common_args,
            "echo",
            "hello",
            password="123",
        )

        output = ssh_client.communicate(timeout=timeout)[0]
        assert b"Warpgate" in output
        assert b"Selected target:" in output
        assert b"hello\r\n" in output

    def test_signals(
        self,
        processes: ProcessManager,
        wg_port,
    ):
        ssh_client = processes.start_ssh_client(
            "-p",
            str(wg_port),
            "-v",
            *common_args,
            "sh",
            "-c",
            '"pkill -9 sh"',
            password="123",
        )

        assert ssh_client.returncode != 0

    def test_direct_tcpip(
        self,
        processes: ProcessManager,
        wg_port,
        timeout,
    ):
        local_port = alloc_port()
        ssh_client = processes.start_ssh_client(
            "-p",
            str(wg_port),
            "-v",
            *common_args,
            "-L",
            f"{local_port}:neverssl.com:80",
            "-N",
            password="123",
        )

        time.sleep(10)

        wait_port(local_port, recv=False)

        s = requests.Session()
        retries = requests.adapters.Retry(total=5, backoff_factor=1)
        s.mount("http://", requests.adapters.HTTPAdapter(max_retries=retries))
        response = s.get(f"http://localhost:{local_port}", timeout=timeout)
        assert response.status_code == 200
        ssh_client.kill()

    def test_tcpip_forward(
        self,
        processes: ProcessManager,
        wg_port,
        timeout,
    ):
        pf_client = processes.start_ssh_client(
            "-p",
            str(wg_port),
            "-v",
            *common_args,
            "-R",
            "1234:neverssl.com:80",
            "-N",
            password="123",
        )
        time.sleep(5)
        ssh_client = processes.start_ssh_client(
            "-p",
            str(wg_port),
            "-v",
            *common_args,
            "curl",
            "-v",
            "http://localhost:1234",
            password="123",
        )
        output = ssh_client.communicate(timeout=timeout)[0]
        print(output)
        assert ssh_client.returncode == 0
        assert b"<html>" in output
        pf_client.kill()

    def test_shell(
        self,
        processes: ProcessManager,
        wg_port,
        timeout,
    ):
        script = dedent(
            f"""
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
            """
        )

        ssh_client = processes.start(
            ["expect", "-d"], stdin=subprocess.PIPE, stdout=subprocess.PIPE
        )

        output = ssh_client.communicate(script.encode(), timeout=timeout)[0]
        assert ssh_client.returncode == 0, output

    def test_connection_error(
        self,
        processes: ProcessManager,
        wg_port,
    ):
        ssh_client = processes.start_ssh_client(
            "-p",
            str(wg_port),
            "-tt",
            "user:ssh-bad-domain@localhost",
            "-i",
            "/dev/null",
            "-o",
            "PreferredAuthentications=password",
            password="123",
        )

        assert ssh_client.returncode != 0

    def test_sftp(
        self,
        wg_port,
    ):
        with tempfile.TemporaryDirectory() as f:
            subprocess.check_call(
                [
                    "sftp",
                    "-P",
                    str(wg_port),
                    "-o",
                    "User=user:ssh",
                    "-o",
                    "IdentitiesOnly=yes",
                    "-o",
                    "IdentityFile=ssh-keys/id_ed25519",
                    "-o",
                    "PreferredAuthentications=publickey",
                    "-o",
                    "StrictHostKeychecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "localhost:/etc/passwd",
                    f,
                ],
                stdout=subprocess.PIPE,
            )

            assert "root:x:0:0:root" in open(f + "/passwd").read()
