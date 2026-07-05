"""Minimal RFB (VNC) client speaking Warpgate's viewer-side auth, for E2E tests.

Warpgate's native VNC server only offers VeNCrypt (X509Plain) and Apple-DH to the
viewer, with the `user:target` selector carried in the VeNCrypt Plain username.
Off-the-shelf Python VNC clients don't speak VeNCrypt, so this implements just
enough of the protocol to drive the tests:

* the VeNCrypt handshake (TLS upgrade + Plain user/password auth),
* reading framebuffer updates (Raw / CopyRect / DesktopSize),
* keyboard / pointer input (e.g. typing a one-time password into the hold screen).

It advertises only Raw, CopyRect and DesktopSize so every framebuffer update it
receives — the hold screen and, after the relay handoff, the backend — is decodable.
"""

import socket
import ssl
import struct

RFB_VERSION = b"RFB 003.008\n"

SEC_VENCRYPT = 19
VENCRYPT_VERSION = bytes([0, 2])
VENCRYPT_SUBTYPE_X509PLAIN = 262

ENC_RAW = 0
ENC_COPYRECT = 1
ENC_DESKTOP_SIZE = -223


class VncError(Exception):
    pass


class VncClient:
    def __init__(self, host, port, username, password, shared=True, timeout=30):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.shared = shared
        self.timeout = timeout
        self.sock = None
        self.width = 0
        self.height = 0
        self.name = ""
        self.bytes_per_pixel = 4

    # -- low-level IO --------------------------------------------------------
    def _recv_exact(self, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise VncError("connection closed by peer")
            buf.extend(chunk)
        return bytes(buf)

    def _send(self, data):
        self.sock.sendall(data)

    def _read_failure_reason(self):
        try:
            length = struct.unpack(">I", self._recv_exact(4))[0]
            return self._recv_exact(length).decode("utf-8", "replace")
        except VncError:
            return "<no reason>"

    # -- handshake -----------------------------------------------------------
    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)

        server_version = self._recv_exact(12)
        if not server_version.startswith(b"RFB "):
            raise VncError(f"bad server version: {server_version!r}")
        self._send(RFB_VERSION)

        n_types = self._recv_exact(1)[0]
        if n_types == 0:
            raise VncError(f"server rejected connection: {self._read_failure_reason()}")
        types = self._recv_exact(n_types)
        if SEC_VENCRYPT not in types:
            raise VncError(f"server does not offer VeNCrypt; offered {list(types)}")
        self._send(bytes([SEC_VENCRYPT]))

        self._vencrypt_subnegotiate()
        self._start_tls()
        self._plain_auth()
        self._read_security_result()

        self._send(bytes([1 if self.shared else 0]))  # ClientInit
        self._read_server_init()
        self.set_encodings()

    def _vencrypt_subnegotiate(self):
        self._recv_exact(2)  # server VeNCrypt version
        self._send(VENCRYPT_VERSION)
        if self._recv_exact(1)[0] != 0:
            raise VncError("server rejected VeNCrypt version")
        n_sub = self._recv_exact(1)[0]
        if n_sub == 0:
            raise VncError("server offered no VeNCrypt subtypes")
        subtypes = [struct.unpack(">I", self._recv_exact(4))[0] for _ in range(n_sub)]
        if VENCRYPT_SUBTYPE_X509PLAIN not in subtypes:
            raise VncError(f"server lacks X509Plain; offered {subtypes}")
        self._send(struct.pack(">I", VENCRYPT_SUBTYPE_X509PLAIN))
        if self._recv_exact(1)[0] != 1:
            raise VncError("server refused VeNCrypt subtype")

    def _start_tls(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.sock = ctx.wrap_socket(self.sock, server_hostname=None)

    def _plain_auth(self):
        user = self.username.encode()
        pw = self.password.encode()
        self._send(struct.pack(">II", len(user), len(pw)) + user + pw)

    def _read_security_result(self):
        if struct.unpack(">I", self._recv_exact(4))[0] != 0:
            raise VncError(f"authentication failed: {self._read_failure_reason()}")

    def _read_server_init(self):
        header = self._recv_exact(20)  # width(2) + height(2) + pixel format(16)
        self.width, self.height = struct.unpack(">HH", header[:4])
        self.bytes_per_pixel = max(1, header[4] // 8)  # bits-per-pixel is the first PF byte
        name_len = struct.unpack(">I", self._recv_exact(4))[0]
        self.name = self._recv_exact(name_len).decode("utf-8", "replace")

    # -- client -> server messages ------------------------------------------
    def set_encodings(self, encodings=(ENC_COPYRECT, ENC_RAW, ENC_DESKTOP_SIZE)):
        msg = bytearray([2, 0])  # SetEncodings + padding
        msg += struct.pack(">H", len(encodings))
        for e in encodings:
            msg += struct.pack(">i", e)
        self._send(bytes(msg))

    def request_framebuffer(self, incremental=False):
        self._send(
            struct.pack(">BBHHHH", 3, 1 if incremental else 0, 0, 0, self.width, self.height)
        )

    def send_key(self, keysym, down):
        self._send(struct.pack(">BBHI", 4, 1 if down else 0, 0, keysym))

    def send_pointer(self, x, y, buttons=0):
        self._send(struct.pack(">BBHH", 5, buttons, x, y))

    def type_text(self, text):
        """Send each character as a key press + release (digits drive the OTP field)."""
        for ch in text:
            self.send_key(ord(ch), True)
            self.send_key(ord(ch), False)

    # -- server -> client messages ------------------------------------------
    def read_message(self):
        """Read one server message. Returns ("framebuffer", [(x, y, w, h, enc), ...]),
        ("bell", None), ("cut_text", str) or ("colourmap", None)."""
        msg_type = self._recv_exact(1)[0]
        if msg_type == 0:
            self._recv_exact(1)  # padding
            n = struct.unpack(">H", self._recv_exact(2))[0]
            rects = []
            for _ in range(n):
                x, y, w, h, enc = struct.unpack(">HHHHi", self._recv_exact(12))
                self._consume_rect(w, h, enc)
                if enc == ENC_DESKTOP_SIZE:
                    self.width, self.height = w, h
                rects.append((x, y, w, h, enc))
            return ("framebuffer", rects)
        if msg_type == 1:
            return ("bell", None)
        if msg_type == 2:
            self._recv_exact(1)  # padding
            _first, count = struct.unpack(">HH", self._recv_exact(4))
            self._recv_exact(count * 6)
            return ("colourmap", None)
        if msg_type == 3:
            self._recv_exact(3)  # padding
            length = struct.unpack(">I", self._recv_exact(4))[0]
            return ("cut_text", self._recv_exact(length).decode("latin-1", "replace"))
        raise VncError(f"unexpected server message type {msg_type}")

    def _consume_rect(self, w, h, enc):
        if enc == ENC_RAW:
            self._recv_exact(w * h * self.bytes_per_pixel)
        elif enc == ENC_COPYRECT:
            self._recv_exact(4)
        elif enc == ENC_DESKTOP_SIZE:
            pass
        else:
            raise VncError(f"cannot decode encoding {enc}")

    def wait_for_resize(self, max_messages=300):
        """Drive the framebuffer until a DesktopSize update arrives — which Warpgate
        sends at the relay handoff to resize the viewer to the backend geometry —
        and return its (width, height)."""
        for _ in range(max_messages):
            self.request_framebuffer(incremental=True)
            kind, rects = self.read_message()
            if kind != "framebuffer":
                continue
            for (_x, _y, w, h, enc) in rects:
                if enc == ENC_DESKTOP_SIZE:
                    return (w, h)
        raise VncError("did not receive a desktop resize")

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
