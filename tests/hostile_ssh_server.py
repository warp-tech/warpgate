"""An SSH server that does not intend to be one.

Every other test in this suite treats the target as honest: a stock `sshd` in a
container that answers correctly or refuses politely. That is the one trust
boundary nothing here has ever pushed on, and it is not a hypothetical — five of
russh's fourteen published advisories are reachable from the peer, including two
pre-authentication panics in the *client* role, which is the role Warpgate plays
here.

A target is added by an administrator, but it lives on a machine Warpgate does
not own. If a compromised host can hang or crash the gateway's client, it takes
down more than its own session — and the certificate feature has Warpgate dial
out, with a freshly minted credential, on every connection.

Each mode below is a way of being wrong that a real server never is.
"""

import socket
import threading

from .util import alloc_port

MODES = {
    # RFC 4253 says the identification string ends with CR LF. Without it a
    # client that reads "until the line ends" reads forever.
    "banner_never_ends": None,
    # Bounded but enormous. A client that buffers the banner before validating
    # its length allocates all of it.
    "banner_gigantic": None,
    # Correct banner, then bytes that are not a packet.
    "garbage_after_banner": None,
    # Correct banner, then nothing at all, forever.
    "silent_after_banner": None,
    # Accept and close immediately.
    "instant_close": None,
    # A packet claiming a length far beyond anything real.
    "absurd_packet_length": None,
}


class HostileSSHServer:
    """Listens on a port and misbehaves in one chosen way."""

    def __init__(self, mode: str):
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode}")
        self.mode = mode
        self.port = alloc_port()
        self.connections = 0
        # Dual-stack: Warpgate resolves the target's hostname and dials the
        # first address it gets, which for `localhost` is usually `::1`. A
        # v4-only listener is simply never reached, and the test then passes for
        # having tested nothing.
        self._socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        self._socket.bind(("::", self.port))
        self._socket.listen(8)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        try:
            self._socket.close()
        except OSError:
            pass
        self._thread.join(timeout=5)

    def _serve(self):
        while not self._stop.is_set():
            try:
                client, _ = self._socket.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(
                target=self._handle, args=(client,), daemon=True
            ).start()

    def _handle(self, client: socket.socket):
        try:
            client.settimeout(30)
            if self.mode == "instant_close":
                client.close()
                return

            if self.mode == "banner_never_ends":
                # No CR LF, ever.
                while not self._stop.is_set():
                    client.sendall(b"SSH-2.0-Endless" + b"A" * 1024)
                return

            if self.mode == "banner_gigantic":
                client.sendall(b"SSH-2.0-Huge" + b"B" * (8 * 1024 * 1024) + b"\r\n")
                return

            client.sendall(b"SSH-2.0-Hostile_1.0\r\n")

            if self.mode == "silent_after_banner":
                while not self._stop.is_set():
                    self._stop.wait(0.5)
                return

            if self.mode == "garbage_after_banner":
                client.sendall(bytes(range(256)) * 64)
                return

            if self.mode == "absurd_packet_length":
                # A binary packet header claiming ~4 GiB of payload. A reader
                # that reserves the declared length before checking it against
                # anything allocates that much.
                client.sendall(b"\xff\xff\xff\xf0" + b"\x00" * 16)
                while not self._stop.is_set():
                    self._stop.wait(0.5)
                return
        except OSError:
            return
        finally:
            try:
                client.close()
            except OSError:
                pass
