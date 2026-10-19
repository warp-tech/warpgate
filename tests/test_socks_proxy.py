import socket
import subprocess
import threading
import time
from contextlib import contextmanager
from uuid import uuid4

import pytest
import requests

from . import socks_client as socks
from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import alloc_port, wait_port


class EchoServer:
    """A TCP echo service standing in for the target behind the tunnel."""

    def __init__(self):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.port = self.listener.getsockname()[1]
        self.accepted = 0
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            self.accepted += 1
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()

    @staticmethod
    def _echo(conn):
        with conn:
            while True:
                try:
                    data = conn.recv(65536)
                    if not data:
                        return
                    conn.sendall(data)
                except OSError:
                    return

    def close(self):
        self.listener.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _url(wg: WarpgateProcess):
    return f"https://localhost:{wg.http_port}"


def _create_target(api, role, port, host="127.0.0.1", rate_limit=None, assign=True):
    target = api.create_target(
        sdk.TargetDataRequest(
            name=f"tcp-{uuid4()}",
            require_approval=False,
            ticket_requests_disabled=False,
            ticket_require_approval=False,
            options=sdk.TargetOptions(
                sdk.TargetOptionsTargetTcpOptions(kind="Tcp", host=host, port=port)
            ),
        )
    )
    if rate_limit:
        api.update_target(
            target.id,
            sdk.TargetDataRequest(
                name=target.name,
                require_approval=False,
                ticket_requests_disabled=False,
                ticket_require_approval=False,
                rate_limit_bytes_per_second=rate_limit,
                options=target.options,
            ),
        )
    if assign:
        api.add_target_role(target.id, role.id)
    return target


def _create_user(api, role, password="123"):
    user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
    if password:
        api.create_password_credential(
            user.id, sdk.NewPasswordCredential(password=password)
        )
    api.add_user_role(user.id, role.id)
    return user


@contextmanager
def _setup(wg: WarpgateProcess):
    """A user with a password, a tcp target in front of an echo server, and the
    names to log in with."""
    wait_port(wg.socks_port, recv=False)
    with EchoServer() as echo, admin_client(_url(wg)) as api:
        role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        user = _create_user(api, role)
        target = _create_target(api, role, echo.port)
        yield type(
            "Setup",
            (),
            {
                "api": api,
                "role": role,
                "user": user,
                "target": target,
                "echo": echo,
                "wg": wg,
                "port": wg.socks_port,
                "selector": f"{user.username}#{target.name}",
            },
        )


@pytest.fixture
def setup(shared_wg: WarpgateProcess):
    with _setup(shared_wg) as s:
        yield s


@pytest.fixture(scope="module")
def quiet_wg(processes: ProcessManager):
    """A gateway that doesn't block an address for failing to log in, for the
    tests that fail on purpose. The shared one would stop answering them."""
    wg = processes.start_wg()
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    with admin_client(_url(wg)) as api:
        api.update_parameters(sdk.ParameterUpdate(login_protection_enabled=False))
    return wg


@pytest.fixture
def denial_setup(quiet_wg: WarpgateProcess):
    with _setup(quiet_wg) as s:
        yield s


def _wait_for_log(api, wanted_type, target_name, timeout=10):
    deadline = time.monotonic() + timeout
    while True:
        found = [
            entry.values
            for entry in api.get_logs(sdk.GetLogsRequest(limit=500))
            if (entry.values or {}).get("_type") == wanted_type
            and (entry.values or {}).get("target_name") == target_name
        ]
        if found or time.monotonic() > deadline:
            return found
        time.sleep(0.2)


class Test:
    def test_password(self, setup):
        with socks.tunnel(
            setup.port, setup.selector, "123", "127.0.0.1", setup.echo.port
        ) as sock:
            sock.sendall(b"hello through the tunnel")
            assert socks.recv_exact(sock, 24) == b"hello through the tunnel"

    def test_session_and_audit_events(self, setup):
        with socks.tunnel(
            setup.port, setup.selector, "123", "127.0.0.1", setup.echo.port
        ) as sock:
            sock.sendall(b"12345")
            assert socks.recv_exact(sock, 5) == b"12345"
            sessions = setup.api.get_sessions(username=setup.user.username).items
            assert len(sessions) == 1
            opened = _wait_for_log(setup.api, "TcpTunnelOpened1", setup.target.name)
            assert opened and opened[0]["username"] == setup.user.username

        closed = _wait_for_log(setup.api, "TcpTunnelClosed1", setup.target.name)
        assert closed, "closing the tunnel must be audited"
        assert closed[0]["reason"] == "closed"
        assert int(closed[0]["bytes_to_target"]) == 5
        assert int(closed[0]["bytes_from_target"]) == 5

    def test_closing_the_session_audits_the_tunnel(self, setup):
        with socks.tunnel(
            setup.port, setup.selector, "123", "127.0.0.1", setup.echo.port
        ) as sock:
            sock.sendall(b"x")
            socks.recv_exact(sock, 1)
            session = setup.api.get_sessions(username=setup.user.username).items[0]
            setup.api.close_session(session.id)
            assert socks.at_eof(sock)

        closed = _wait_for_log(setup.api, "TcpTunnelClosed1", setup.target.name)
        assert closed and closed[0]["reason"] == "aborted"

    def test_domain_name_request(self, shared_wg: WarpgateProcess):
        wait_port(shared_wg.socks_port, recv=False)
        with EchoServer() as echo, admin_client(_url(shared_wg)) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = _create_user(api, role)
            target = _create_target(api, role, echo.port, host="localhost")

            with socks.tunnel(
                shared_wg.socks_port,
                f"{user.username}:{target.name}",
                "123",
                "LOCALHOST",
                echo.port,
            ) as sock:
                sock.sendall(b"ping")
                assert socks.recv_exact(sock, 4) == b"ping"

            # a name is not the IP it resolves to
            with socks.login(
                shared_wg.socks_port, f"{user.username}:{target.name}", "123"
            ) as sock:
                socks.send_request(
                    sock,
                    socks.CMD_CONNECT,
                    socks.address_bytes("127.0.0.1"),
                    echo.port,
                )
                assert socks.read_reply(sock) == socks.REPLY_NOT_ALLOWED

    def test_only_the_configured_address_is_served(self, setup):
        for host, port in [
            ("127.0.0.1", setup.echo.port + 1),
            ("127.0.0.2", setup.echo.port),
            ("::1", setup.echo.port),
            ("example.com", 80),
        ]:
            with socks.login(setup.port, setup.selector, "123") as sock:
                socks.send_request(
                    sock, socks.CMD_CONNECT, socks.address_bytes(host), port
                )
                assert socks.read_reply(sock) == socks.REPLY_NOT_ALLOWED, (host, port)
                assert socks.at_eof(sock)
        assert setup.echo.accepted == 0

    def test_other_commands_and_address_types(self, setup):
        for command in (socks.CMD_BIND, socks.CMD_UDP_ASSOCIATE):
            with socks.login(setup.port, setup.selector, "123") as sock:
                socks.send_request(sock, command, socks.address_bytes("0.0.0.0"), 0)
                assert socks.read_reply(sock) == socks.REPLY_COMMAND_NOT_SUPPORTED

        with socks.login(setup.port, setup.selector, "123") as sock:
            sock.sendall(b"\x05\x01\x00\x09" + b"\x00" * 6)
            assert socks.read_reply(sock) == socks.REPLY_ADDRESS_TYPE_NOT_SUPPORTED

    def test_authentication_methods(self, setup):
        # no-auth (and GSSAPI) are never accepted
        for methods in [(0x00,), (0x00, 0x01), ()]:
            with socks.connect(setup.port) as sock:
                assert socks.greet(sock, methods) == b"\x05\xff"
                assert socks.at_eof(sock)

        # a client that also offers no-auth still gets username/password
        with socks.connect(setup.port) as sock:
            assert socks.greet(sock, (0x00, 0x02)) == b"\x05\x02"

        # not SOCKS5: dropped without an answer
        with socks.connect(setup.port) as sock:
            sock.sendall(b"\x04\x01\x00\x50\x7f\x00\x00\x01\x00")
            assert socks.at_eof(sock)

        # wrong RFC 1929 sub-negotiation version
        with socks.connect(setup.port) as sock:
            socks.greet(sock)
            sock.sendall(b"\x02\x01a\x01b")
            assert socks.at_eof(sock)

    def test_refused_target(self, shared_wg: WarpgateProcess):
        wait_port(shared_wg.socks_port, recv=False)
        closed_port = alloc_port()
        with admin_client(_url(shared_wg)) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = _create_user(api, role)
            target = _create_target(api, role, closed_port)
            with socks.login(
                shared_wg.socks_port, f"{user.username}#{target.name}", "123"
            ) as sock:
                socks.send_request(
                    sock, socks.CMD_CONNECT, socks.address_bytes("127.0.0.1"), closed_port
                )
                assert socks.read_reply(sock) == socks.REPLY_CONNECTION_REFUSED

    def test_ticket(self, setup):
        secret = setup.api.create_ticket(
            sdk.CreateTicketRequest(
                target_name=setup.target.name,
                username=setup.user.username,
                number_of_uses=1,
            )
        ).secret

        # a ticket is presented as the username; the password is unused
        with socks.tunnel(
            setup.port, f"ticket-{secret}", "", "127.0.0.1", setup.echo.port
        ) as sock:
            sock.sendall(b"ticket")
            assert socks.recv_exact(sock, 6) == b"ticket"

    def test_curl(self, setup, processes: ProcessManager, timeout):
        """A real client: curl resolves nothing itself with socks5h."""
        http = _HttpServer()
        try:
            target = _create_target(
                setup.api, setup.role, http.port, host="localhost"
            )
            client = processes.start(
                [
                    "curl",
                    "--silent",
                    "--show-error",
                    "--proxy",
                    f"socks5h://127.0.0.1:{setup.port}",
                    "--proxy-user",
                    f"{setup.user.username}#{target.name}:123",
                    f"http://localhost:{http.port}/",
                ],
                stdout=subprocess.PIPE,
            )
            out = client.communicate(timeout=timeout)[0]
            assert client.returncode == 0
            assert out == b"hello from the target"
        finally:
            http.close()

    def test_rate_limit_applies_to_the_tunnel(self, shared_wg: WarpgateProcess):
        wait_port(shared_wg.socks_port, recv=False)
        size = 100_000
        rate = 20_000

        def transfer(selector, echo_port):
            payload = b"x" * size
            with socks.tunnel(
                shared_wg.socks_port, selector, "123", "127.0.0.1", echo_port, timeout=60
            ) as sock:
                started = time.monotonic()
                sender = threading.Thread(target=sock.sendall, args=(payload,))
                sender.start()
                assert socks.recv_exact(sock, size) == payload
                sender.join()
                return time.monotonic() - started

        with EchoServer() as echo, admin_client(_url(shared_wg)) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = _create_user(api, role)
            free = _create_target(api, role, echo.port)
            limited = _create_target(api, role, echo.port, rate_limit=rate)

            unlimited_time = transfer(f"{user.username}#{free.name}", echo.port)
            limited_time = transfer(f"{user.username}#{limited.name}", echo.port)

        # the limiter lets one second's worth through at once, so 100 kB at
        # 20 kB/s takes about four seconds
        assert limited_time >= 3, limited_time
        assert unlimited_time < limited_time / 2, (unlimited_time, limited_time)


class TestDenials:
    @pytest.fixture
    def setup(self, denial_setup):
        return denial_setup

    def test_failed_logins_are_indistinguishable(self, setup):
        outsider = _create_user(
            setup.api,
            setup.api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}")),
        )
        attempts = {
            "wrong password": (setup.selector, "wrong"),
            "unknown user": (f"nobody-{uuid4()}#{setup.target.name}", "123"),
            "unknown target": (f"{setup.user.username}#nope-{uuid4()}", "123"),
            "target without access": (f"{outsider.username}#{setup.target.name}", "123"),
            "no target": (setup.user.username, "123"),
        }
        for what, (username, password) in attempts.items():
            sock = socks.connect(setup.port)
            with sock:
                assert socks.greet(sock) == b"\x05\x02"
                assert socks.authenticate(sock, username, password) == socks.AUTH_DENIED, what
                assert socks.at_eof(sock), what

    def test_unauthorised_target(self, setup):
        target = _create_target(setup.api, setup.role, setup.echo.port, assign=False)
        other = _create_user(
            setup.api, setup.api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        )
        for user in (setup.user, other):
            with socks.connect(setup.port) as sock:
                socks.greet(sock)
                assert (
                    socks.authenticate(sock, f"{user.username}#{target.name}", "123")
                    == socks.AUTH_DENIED
                )

    def test_ticket_is_not_accepted_as_a_password(self, setup):
        secret = setup.api.create_ticket(
            sdk.CreateTicketRequest(
                target_name=setup.target.name,
                username=setup.user.username,
            )
        ).secret
        with socks.connect(setup.port) as sock:
            socks.greet(sock)
            assert (
                socks.authenticate(sock, setup.selector, f"ticket-{secret}")
                == socks.AUTH_DENIED
            )

    def test_otp_policy_user_needs_a_ticket(self, setup, otp_key_base64):
        from base64 import b64decode

        setup.api.create_otp_credential(
            setup.user.id,
            sdk.NewOtpCredential(secret_key=list(b64decode(otp_key_base64))),
        )
        setup.api.update_user(
            setup.user.id,
            sdk.UserDataRequest(
                username=setup.user.username,
                credential_policy=sdk.UserRequireCredentialsPolicy(
                    tcp=["Password", "Totp"],
                ),
            ),
        )

        # SOCKS5 has nowhere to ask for the code
        with socks.connect(setup.port) as sock:
            socks.greet(sock)
            assert socks.authenticate(sock, setup.selector, "123") == socks.AUTH_DENIED

        secret = setup.api.create_ticket(
            sdk.CreateTicketRequest(
                target_name=setup.target.name,
                username=setup.user.username,
            )
        ).secret
        with socks.tunnel(
            setup.port, f"ticket-{secret}", "", "127.0.0.1", setup.echo.port
        ) as sock:
            sock.sendall(b"otp")
            assert socks.recv_exact(sock, 3) == b"otp"

    def test_a_spent_ticket_is_refused(self, setup):
        secret = setup.api.create_ticket(
            sdk.CreateTicketRequest(
                target_name=setup.target.name,
                username=setup.user.username,
                number_of_uses=1,
            )
        ).secret
        with socks.tunnel(
            setup.port, f"ticket-{secret}", "", "127.0.0.1", setup.echo.port
        ):
            pass

        # and the single use is spent
        with socks.connect(setup.port) as sock:
            socks.greet(sock)
            assert socks.authenticate(sock, f"ticket-{secret}", "") == socks.AUTH_DENIED


def _lp_wg(processes: ProcessManager, ip_max=100, user_max=100):
    """A gateway with its own login protection thresholds."""
    wg = processes.start_wg()
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    with admin_client(_url(wg)) as api:
        api.update_parameters(
            sdk.ParameterUpdate(
                login_protection_enabled=True,
                lp_ip_max_attempts=ip_max,
                lp_ip_time_window_seconds=600,
                lp_ip_base_block_duration_seconds=120,
                lp_ip_block_duration_multiplier=2.0,
                lp_ip_max_block_duration_seconds=3600,
                lp_ip_cooldown_reset_seconds=3600,
                lp_user_max_attempts=user_max,
                lp_user_time_window_seconds=600,
                lp_user_auto_unlock=True,
                lp_user_lockout_duration_seconds=120,
            )
        )
    return wg


def _denied(setup, username, password):
    with socks.connect(setup.port) as sock:
        socks.greet(sock)
        return socks.authenticate(sock, username, password) == socks.AUTH_DENIED


class TestLoginProtection:
    """The listener shares the gateway's brute-force protection."""

    def test_user_lockout(self, processes: ProcessManager):
        with _setup(_lp_wg(processes, user_max=3)) as setup:
            for _ in range(3):
                assert _denied(setup, setup.selector, "wrong")
            # locked: even the right password is refused now
            assert _denied(setup, setup.selector, "123")

            other = _create_user(setup.api, setup.role)
            with socks.tunnel(
                setup.port,
                f"{other.username}#{setup.target.name}",
                "123",
                "127.0.0.1",
                setup.echo.port,
            ):
                pass

    def test_ip_block(self, processes: ProcessManager):
        with _setup(_lp_wg(processes, ip_max=3)) as setup:
            for i in range(3):
                assert _denied(setup, f"nobody-{i}#{setup.target.name}", "wrong")
            assert setup.api.get_security_status().blocked_ip_count >= 1
            # the address is blocked, whoever is asking
            assert _denied(setup, setup.selector, "123")


class _HttpServer:
    def __init__(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"hello from the target"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class TestListener:
    def test_off_by_default(self, processes: ProcessManager):
        wg = processes.start_wg(config_patch={"socks": {"enable": False}})
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", wg.socks_port), timeout=2).close()

    def test_refuses_a_non_loopback_address_unless_allowed(
        self, processes: ProcessManager
    ):
        port = alloc_port()
        wg = processes.start_wg(config_patch={"socks": {"listen": f"0.0.0.0:{port}"}})
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        # the listener is paused, the rest of the gateway is up
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=2).close()
        assert requests.get(
            f"https://localhost:{wg.http_port}/@warpgate/api/info", verify=False
        ).ok

        port = alloc_port()
        wg = processes.start_wg(
            config_patch={"socks": {"listen": f"0.0.0.0:{port}", "allow_cleartext": True}}
        )
        wait_port(port, for_process=wg.process, recv=False)
