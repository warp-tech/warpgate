"""A jump host that authenticates you and then never opens the tunnel.

The six modes in `hostile_ssh_server.py` all fail at or before the banner, which
is enough to exercise the outbound handshake deadline and nothing past it. This
one has to speak real SSH — complete key exchange, accept an authentication —
because the step under test comes after both: `channel_open_direct_tcpip`, the
request that asks a jump host to reach the next hop.

That step had no bound of its own. Each hop's deadline is armed inside
`wait_for_connection`, which runs *after* the tunnel is open, so a jump host that
accepts the request and answers nothing stalled the connection for as long as the
previous hop's inactivity timeout allowed — five minutes by default, hours
wherever an operator has raised it for interactive sessions.

Password auth deliberately: the point is the tunnel step, and making the jump
host negotiate an OpenSSH certificate would put paramiko's algorithm support in
the middle of a test about something else.
"""

import socket
import threading

import paramiko

from .util import alloc_port

PASSWORD = "let-me-through"


class _Server(paramiko.ServerInterface):
    def __init__(self, opened: threading.Event, stop: threading.Event):
        self.opened = opened
        # The server's own event, not a fresh one: waiting on a throwaway
        # `threading.Event()` cannot be released by `stop()`, so the transport
        # thread held the accepted socket for the full 300 seconds after the
        # test had finished.
        self.stop = stop

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        if password == PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        """Accept the request and answer nothing.

        Paramiko calls this on the transport thread, so blocking here is exactly
        the behaviour being simulated: the peer has the request and sends back
        neither a confirmation nor a failure. Longer than the deadline under
        test, so the client is the one that gives up.
        """
        self.opened.set()
        self.stop.wait(300)
        return paramiko.OPEN_FAILED_CONNECT_FAILED


class StallingJumpHost:
    """Listens on a port, authenticates, and stalls on the tunnel request."""

    def __init__(self):
        self.port = alloc_port()
        self.tunnel_requested = threading.Event()
        self.connections = 0
        self._stop = threading.Event()
        self._sock = None
        self._thread = None

    def start(self):
        # Dual-stack, for the reason `hostile_ssh_server.py` gives: Warpgate
        # dials `localhost` and takes the first address it resolves, which here
        # is `::1`. A v4-only listener is never reached at all, and the test then
        # passes for having tested nothing — which is exactly what happened on
        # the first run of this one.
        self._sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        self._sock.bind(("::", self.port))
        self._sock.listen(8)
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def _serve(self):
        host_key = paramiko.RSAKey.generate(2048)
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except OSError:
                continue
            self.connections += 1
            threading.Thread(
                target=self._session, args=(client, host_key), daemon=True
            ).start()

    def _session(self, client, host_key):
        try:
            transport = paramiko.Transport(client)
            transport.add_server_key(host_key)
            transport.start_server(server=_Server(self.tunnel_requested, self._stop))
            # The stall happens on the transport thread inside
            # `check_channel_direct_tcpip_request`; nothing to do here but hold
            # the session open until the client gives up or the test ends.
            self._stop.wait(300)
        except Exception:
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass

    def stop(self):
        self._stop.set()
        if self._sock is not None:
            self._sock.close()
