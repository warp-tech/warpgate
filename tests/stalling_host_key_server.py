"""A server that presents a host key and then stops talking.

The narrow window this exists to cover: Warpgate pauses its handshake deadline
while a host key is being decided on, because that wait can legitimately be a
person reading a fingerprint. The first version of that pause never ended — the
deadline was reset to a year out and nothing re-armed it — so a target that
offered an unknown key and then went silent was bounded by nothing except the
inactivity timeout, which is five minutes by default and hours wherever an
operator has raised it for interactive use.

Reproducing it needs the stall to land *between* the host key arriving and the
transport finishing, which is a couple of messages wide. So this server sends
everything up to and including the key exchange reply — the message that carries
the host key — and then sends nothing further, in particular no NEWKEYS. The
client has the key, answers the question, and then waits forever for a handshake
that will not complete.

Stalling later, on authentication, would not test this: by then the transport is
done, `connect` has returned, and a different bound applies.
"""

import socket
import threading

import paramiko

from .util import alloc_port

# The key exchange replies that carry the server's host key. Everything up to
# one of these is sent normally; nothing after it is sent at all.
KEXDH_REPLY = 31
KEX_ECDH_REPLY = 33


class _MuteAfterHostKey(paramiko.Transport):
    """Sends the host key, then drops every outbound message."""

    def __init__(self, sock, delivered: threading.Event):
        super().__init__(sock)
        self._delivered = delivered
        self._mute = False

    def _send_message(self, data):
        if self._mute:
            return
        # `asbytes()` on a Message gives the packet with its type byte first.
        raw = data.asbytes() if hasattr(data, "asbytes") else bytes(data)
        kind = raw[0] if raw else 0
        super()._send_message(data)
        if kind in (KEXDH_REPLY, KEX_ECDH_REPLY):
            self._mute = True
            self._delivered.set()


class _Server(paramiko.ServerInterface):
    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        return paramiko.AUTH_FAILED


class StallingHostKeyServer:
    """Listens on a port, offers a host key nobody has seen, then goes quiet."""

    def __init__(self):
        self.port = alloc_port()
        self.key_delivered = threading.Event()
        self.connections = 0
        self._stop = threading.Event()
        self._sock = None
        self._thread = None

    def start(self):
        # Dual-stack, for the reason `hostile_ssh_server.py` gives: Warpgate
        # dials `localhost` and takes the first address it resolves, which here
        # is `::1`. A v4-only listener is never reached, and the test then
        # passes for having tested nothing.
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
        # Generated per instance, so it is a key Warpgate has never trusted and
        # the unknown-host-key branch is the one that runs.
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
        transport = None
        try:
            transport = _MuteAfterHostKey(client, self.key_delivered)
            transport.add_server_key(host_key)
            # Returns once the handshake stalls or fails; either way the socket
            # is held open below so the client is the one that gives up.
            transport.start_server(server=_Server())
        except Exception:
            pass
        finally:
            self._stop.wait(300)
            try:
                if transport is not None:
                    transport.close()
                client.close()
            except OSError:
                pass

    def stop(self):
        self._stop.set()
        if self._sock is not None:
            self._sock.close()
