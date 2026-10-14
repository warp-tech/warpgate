import socket
import time
from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .approval_util import default_params
from .conftest import ProcessManager
from .test_ssh_proto import common_args, setup_user_and_target
from .util import read_until, wait_port

# Long enough for a normal loopback handshake, short enough to keep the test
# quick.
HANDSHAKE_TIMEOUT = 3
TIMEOUT_MESSAGE = b"SSH handshake timed out"
HOST_KEY_PROMPT = b"Trust this key? (y/n)"

config_patch = {"ssh": {"target_handshake_timeout": f"{HANDSHAKE_TIMEOUT}s"}}


@pytest.fixture
def silent_ssh_port():
    # Nothing calls accept(), so the kernel completes the TCP handshake on its
    # own and the backlog holds the connection open. No data is ever sent on it.
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    yield listener.getsockname()[1]
    listener.close()


class Test:
    def test_silent_target_fails_instead_of_hanging(
        self,
        processes: ProcessManager,
        timeout,
        silent_ssh_port,
    ):
        wg = processes.start_wg(config_patch=config_patch)
        wait_port(wg.http_port, recv=False)
        wait_port(wg.ssh_port)

        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id)
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            allow_insecure_algos=False,
                            host="127.0.0.1",
                            port=silent_ssh_port,
                            username="root",
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(
                                    kind="PublicKey"
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(target.id, role.id)

        client = processes.start_ssh_client(
            f"{user.username}:{target.name}@localhost",
            "-p",
            str(wg.ssh_port),
            "-tt",
            *common_args,
            "echo",
            "never-runs",
            password="123",
        )

        output = read_until(client.stdout, TIMEOUT_MESSAGE, time.monotonic() + timeout)
        assert TIMEOUT_MESSAGE in output, output
        assert client.wait(timeout=timeout) != 0

    def test_host_key_prompt_is_not_interrupted(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
    ):
        wg = processes.start_wg(config_patch=config_patch)
        wait_port(wg.http_port, recv=False)
        wait_port(wg.ssh_port)

        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            api.update_parameters(default_params(ssh_host_key_verification="Prompt"))

        user, target = setup_user_and_target(processes, wg, wg_c_ed25519_pubkey)

        marker = f"trusted-{uuid4().hex}"
        client = processes.start_ssh_client(
            f"{user.username}:{target.name}@localhost",
            "-p",
            str(wg.ssh_port),
            "-tt",
            *common_args,
            "echo",
            marker,
            password="123",
        )

        prompt = read_until(client.stdout, HOST_KEY_PROMPT, time.monotonic() + timeout)
        assert HOST_KEY_PROMPT in prompt, prompt

        # Leave it unanswered for longer than the deadline.
        time.sleep(HANDSHAKE_TIMEOUT * 2)

        # Warpgate compares the whole chunk to b"y", so send that byte alone.
        client.stdin.write(b"y")
        client.stdin.flush()

        output = read_until(client.stdout, marker.encode(), time.monotonic() + timeout)
        assert marker.encode() in output, output
        assert TIMEOUT_MESSAGE not in output
