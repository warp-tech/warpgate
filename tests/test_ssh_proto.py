from uuid import uuid4
import os
import paramiko
import requests
import socket
import subprocess
import tempfile
import time
import pytest
from textwrap import dedent

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port, alloc_port


@pytest.fixture(scope="session")
def ssh_port(processes, wg_c_ed25519_pubkey):
    yield processes.start_ssh_server(trusted_keys=[wg_c_ed25519_pubkey.read_text()])


common_args = [
    "-i",
    "/dev/null",
    "-o",
    "PreferredAuthentications=password",
]


def setup_user_and_target(
    processes: ProcessManager,
    wg: WarpgateProcess,
    warpgate_client_key,
    extra_config='',
):
    ssh_port = processes.start_ssh_server(
        trusted_keys=[warpgate_client_key.read_text()],
        extra_config=extra_config,
    )
    wait_port(ssh_port)

    url = f"https://localhost:{wg.http_port}"
    with admin_client(url) as api:
        role = api.create_role(
            sdk.RoleDataRequest(name=f"role-{uuid4()}"),
        )
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        api.create_password_credential(
            user.id, sdk.NewPasswordCredential(password="123")
        )
        api.create_public_key_credential(
            user.id,
            sdk.NewPublicKeyCredential(
                label="Public Key",
                openssh_public_key=open("ssh-keys/id_ed25519.pub").read().strip(),
            ),
        )
        api.add_user_role(user.id, role.id)
        ssh_target = api.create_target(
            sdk.TargetDataRequest(
                name=f"ssh-{uuid4()}",
                options=sdk.TargetOptions(
                    sdk.TargetOptionsTargetSSHOptions(
                        kind="Ssh",
                        host="localhost",
                        port=ssh_port,
                        username="root",
                        auth=sdk.SSHTargetAuth(
                            sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                        ),
                    )
                ),
            )
        )
        api.add_target_role(ssh_target.id, role.id)
        return user, ssh_target


class Test:
    def test_stdout_stderr(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        user, ssh_target = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
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
        timeout,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        user, ssh_target = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-tt",
            *common_args,
            "echo",
            "hello",
            password="123",
        )

        output = ssh_client.communicate(timeout=timeout)[0]
        assert ssh_target.name.encode() in output
        assert b"hello\r\n" in output

    def test_signals(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        user, ssh_target = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
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
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
        timeout,
    ):
        user, ssh_target = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )
        local_port = alloc_port()
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-v",
            *common_args,
            "-L",
            f"{local_port}:github.com:443",
            "-N",
            password="123",
        )

        time.sleep(10)

        wait_port(local_port, recv=False)

        s = requests.Session()
        retries = requests.adapters.Retry(total=5, backoff_factor=1)
        s.mount("https://", requests.adapters.HTTPAdapter(max_retries=retries))
        response = s.get(f"https://localhost:{local_port}", timeout=timeout, verify=False)
        assert response.status_code == 200
        ssh_client.kill()

    # https://github.com/warp-tech/warpgate/issues/2328
    def test_direct_tcpip_server_speaks_first(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
        timeout,
    ):
        # The first direct-tcpip channel to a given host:port must deliver bytes
        # the target sends on its own, before the client writes anything (#2328).
        # The target's own sshd (localhost:22 inside the container) greets with an
        # SSH-2.0 banner immediately, so it is a convenient server-first peer.
        #
        # On the buggy code the channel-open confirmation races the target's first
        # bytes and can lose, so the client never sees the banner. The race is
        # timing-sensitive: a single connection is flaky, but the first channel to
        # a host:port in a *fresh* session reliably loses often enough that a
        # handful of fresh sessions makes the regression deterministic. Recording
        # is left at its default (on) — that is the exact scenario reported.
        user, ssh_target = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        checked = 0
        spawns = 0
        while checked < 8:
            # An ssh client that dies before the listener is up (sshpass
            # occasionally garbles the password on this kind of rapid spawn
            # loop) never opened a channel, so it can't count as a pass —
            # respawn it, within a budget that still fails on systemic death.
            spawns += 1
            assert spawns <= 12, "too many ssh client startup failures"

            local_port = alloc_port()
            ssh_client = processes.start_ssh_client(
                f"{user.username}:{ssh_target.name}@localhost",
                "-p",
                str(shared_wg.ssh_port),
                *common_args,
                "-L",
                f"{local_port}:localhost:22",
                "-N",
                password="123",
            )
            try:
                # Do not probe the port first: every accepted connection opens a
                # fresh channel. A refused connection (listener not up yet) opens
                # nothing, so retrying the connect is safe — the first one that
                # succeeds is channel #1.
                deadline = time.time() + timeout
                conn = None
                while time.time() < deadline and ssh_client.poll() is None:
                    try:
                        conn = socket.create_connection(
                            ("localhost", local_port), timeout=5
                        )
                        break
                    except socket.error:
                        time.sleep(0.1)
                if conn is None:
                    assert ssh_client.poll() is not None, (
                        f"check {checked}: forwarded port never came up"
                    )
                    continue

                conn.settimeout(8)
                try:
                    banner = conn.recv(100)
                except socket.timeout:
                    banner = b""
                finally:
                    conn.close()

                assert banner.startswith(b"SSH-2.0"), (
                    f"check {checked}: first-channel banner never arrived "
                    f"(got {banner!r}) — server-first bytes were dropped"
                )
                checked += 1
            finally:
                ssh_client.kill()

    # https://github.com/warp-tech/warpgate/issues/2494
    def test_output_survives_a_stalled_client_window(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
        timeout,
    ):
        # A client that stops draining a channel shuts its receive window, so
        # Warpgate's writes towards it queue up. If the session event loop parks
        # on one of those writes it can no longer answer the russh handler — and
        # the russh reader, blocked inside that handler, is the only thing that
        # can process the window update that would release the write. What parks
        # the reader is client->server traffic while the window is shut, so the
        # test sends some before draining.
        #
        # paramiko only replenishes the window from recv(), which gives the
        # precise control over draining that OpenSSH does not.
        user, ssh_target = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        transport = paramiko.Transport(("localhost", shared_wg.ssh_port))
        try:
            transport.connect(
                username=f"{user.username}:{ssh_target.name}", password="123"
            )
            channel = transport.open_session()
            channel.settimeout(timeout)
            # More than everything in the path can hold: the client window, the
            # window Warpgate advertises to the target, and Warpgate's queues.
            channel.exec_command("head -c 67108864 /dev/zero")

            time.sleep(3)
            for _ in range(10):
                channel.sendall(b"x" * 4096)
                time.sleep(0.2)

            # Past the 2 MB paramiko had already buffered, so this can only be
            # satisfied by a session that is still moving data.
            wanted = 4 * 1024 * 1024
            received = 0
            while received < wanted:
                try:
                    chunk = channel.recv(65536)
                except socket.timeout:
                    raise AssertionError(
                        f"transfer stalled after {received} of {wanted} bytes"
                    )
                assert chunk, f"channel closed after {received} of {wanted} bytes"
                received += len(chunk)
        finally:
            transport.close()

    # https://github.com/warp-tech/warpgate/issues/2498
    def test_direct_tcpip_stuck_open_does_not_block_siblings(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
        timeout,
    ):
        # A direct-tcpip destination that never answers leaves the target's
        # sshd blocked in connect() with no timeout, so warpgate never gets a
        # CHANNEL_OPEN reply. That open used to be awaited on the per-session
        # command loop, freezing every other channel of the session (#2498).
        user, ssh_target = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        blackhole_port = alloc_port()
        good_port = alloc_port()
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            *common_args,
            # TEST-NET-1: routable-looking, answered by nobody
            "-L",
            f"{blackhole_port}:192.0.2.1:80",
            "-L",
            f"{good_port}:localhost:22",
            "-N",
            password="123",
        )
        try:
            deadline = time.time() + timeout
            stuck = None
            while time.time() < deadline and ssh_client.poll() is None:
                try:
                    stuck = socket.create_connection(
                        ("localhost", blackhole_port), timeout=5
                    )
                    break
                except socket.error:
                    time.sleep(0.1)
            assert stuck is not None, "forwarded port never came up"

            # Confirm 192.0.2.1 really is a black hole here: if the network
            # answers with an RST or an ICMP unreachable, the open resolves and
            # there is nothing to be blocked by.
            stuck.settimeout(5)
            try:
                if stuck.recv(1) == b"":
                    pytest.skip("192.0.2.1 is not a black hole on this network")
            except socket.timeout:
                pass

            # The stuck open is now in flight. A sibling channel to a
            # known-good destination must still open and deliver bytes.
            sibling = socket.create_connection(("localhost", good_port), timeout=10)
            try:
                sibling.settimeout(10)
                banner = sibling.recv(100)
            finally:
                sibling.close()
            stuck.close()

            assert banner.startswith(b"SSH-2.0"), (
                f"sibling channel got {banner!r} — a stuck direct-tcpip open "
                f"is blocking the rest of the session"
            )
        finally:
            ssh_client.kill()

    def test_agent_forwarding_parallel(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
        timeout,
    ):
        # Parallel access to the forwarded agent used to deadlock the
        # session event loop (#1459)
        user, ssh_target = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        agent_dir = tempfile.mkdtemp()
        agent_sock = f"{agent_dir}/agent.sock"
        processes.start(["ssh-agent", "-D", "-a", agent_sock])
        for _ in range(100):
            if os.path.exists(agent_sock):
                break
            time.sleep(0.1)

        key_path = f"{agent_dir}/key"
        subprocess.check_call(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", key_path])
        env = {**os.environ, "SSH_AUTH_SOCK": agent_sock}
        subprocess.check_call(["ssh-add", key_path], env=env)

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-v",
            *common_args,
            "-A",
            "ssh-add -L & ssh-add -L & ssh-add -L & wait",
            password="123",
            env=env,
        )
        output = ssh_client.communicate(timeout=timeout)[0]
        assert ssh_client.returncode == 0
        assert output.count(b"ssh-ed25519") == 3

    def test_tcpip_forward(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
        timeout,
    ):
        user, ssh_target = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )
        fw_port = alloc_port()
        pf_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-v",
            *common_args,
            "-R",
            f"{fw_port}:www.google.com:443",
            "-N",
            password="123",
        )
        # time.sleep(5)
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-v",
            *common_args,
            "curl",
            "-vk",
            "--http1.1",
            "-H", "Host: www.google.com",
            f"https://localhost:{fw_port}",
            password="123",
        )
        output = ssh_client.communicate(timeout=timeout)[0]
        assert ssh_client.returncode == 0
        assert b"</html>" in output
        pf_client.kill()

    def test_shell(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
        timeout,
    ):
        user, ssh_target = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )
        script = dedent(
            f"""
            set timeout {timeout - 5}

            spawn ssh -tt {user.username}:{ssh_target.name}@localhost -p {shared_wg.ssh_port} -o StrictHostKeychecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password

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
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        user, ssh_target = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
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
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        user, ssh_target = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )
        with tempfile.TemporaryDirectory() as f:
            subprocess.check_call(
                [
                    "sftp",
                    "-P",
                    str(shared_wg.ssh_port),
                    "-o",
                    f"User={user.username}:{ssh_target.name}",
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

    def test_insecure_protos(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_rsa_pubkey,
        shared_wg: WarpgateProcess,
    ):
        user, ssh_target = setup_user_and_target(
            processes, shared_wg, wg_c_rsa_pubkey,
            extra_config='''
            PubkeyAcceptedKeyTypes=ssh-rsa
            ''',
        )

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            *common_args,
            "echo", "123",
            password="123",
            stderr=subprocess.PIPE,
        )

        ssh_client.wait(timeout=timeout)
        assert ssh_client.returncode != 0

        ssh_target.options.actual_instance.allow_insecure_algos = True
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            api.update_target(ssh_target.id, sdk.TargetDataRequest(
                name=ssh_target.name,
                options=ssh_target.options,
            ))

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            *common_args,
            "echo", "123",
            password="123",
        )

        stdout, _ = ssh_client.communicate(timeout=timeout)
        assert b"123\n" == stdout
