"""A minimal SOCKS5 client over a raw socket (RFC 1928 / RFC 1929), so tests can
speak the protocol byte by byte, including the parts a real client never sends."""

import ipaddress
import socket
import struct

REPLY_SUCCEEDED = 0x00
REPLY_NOT_ALLOWED = 0x02
REPLY_HOST_UNREACHABLE = 0x04
REPLY_CONNECTION_REFUSED = 0x05
REPLY_COMMAND_NOT_SUPPORTED = 0x07
REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 0x08

CMD_CONNECT = 1
CMD_BIND = 2
CMD_UDP_ASSOCIATE = 3

AUTH_DENIED = b"\x01\x01"
AUTH_OK = b"\x01\x00"


class SocksClosed(Exception):
    """The peer closed the connection before sending what was expected."""


def recv_exact(sock: socket.socket, length: int) -> bytes:
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise SocksClosed(f"got {data!r} before the connection closed")
        data += chunk
    return data


def at_eof(sock: socket.socket) -> bool:
    """Whether the peer has closed the connection. A server that closes with
    unread input pending resets it instead of ending it cleanly; both count."""
    try:
        return sock.recv(1) == b""
    except ConnectionResetError:
        return True
    except (TimeoutError, socket.timeout):
        return False


def connect(port: int, timeout: float = 10) -> socket.socket:
    return socket.create_connection(("127.0.0.1", port), timeout=timeout)


def greet(sock: socket.socket, methods=(0x02,)) -> bytes:
    sock.sendall(bytes([5, len(methods), *methods]))
    return recv_exact(sock, 2)


def authenticate(sock: socket.socket, username: str, password: str) -> bytes:
    user, pw = username.encode(), password.encode()
    sock.sendall(bytes([1, len(user)]) + user + bytes([len(pw)]) + pw)
    return recv_exact(sock, 2)


def address_bytes(host: str) -> bytes:
    """ATYP + address for an IP literal or a domain name."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        name = host.encode()
        return bytes([3, len(name)]) + name
    return bytes([1 if ip.version == 4 else 4]) + ip.packed


def send_request(sock: socket.socket, command: int, atyp_and_address: bytes, port: int):
    sock.sendall(bytes([5, command, 0]) + atyp_and_address + struct.pack(">H", port))


def read_reply(sock: socket.socket) -> int:
    """Reads a full reply and returns its reply code."""
    version, code, _reserved, atyp = recv_exact(sock, 4)
    assert version == 5
    length = {1: 4, 4: 16}.get(atyp)
    if length is None:
        length = recv_exact(sock, 1)[0]
    recv_exact(sock, length + 2)
    return code


def login(port: int, username: str, password: str, timeout: float = 10) -> socket.socket:
    """Greeting and authentication, ready for a request. Fails if denied."""
    sock = connect(port, timeout)
    try:
        assert greet(sock) == b"\x05\x02"
        assert authenticate(sock, username, password) == AUTH_OK
    except BaseException:
        sock.close()
        raise
    return sock


def tunnel(
    port: int,
    username: str,
    password: str,
    host: str,
    target_port: int,
    timeout: float = 10,
) -> socket.socket:
    """A fully established CONNECT tunnel; raises if any step is refused."""
    sock = login(port, username, password, timeout)
    try:
        send_request(sock, CMD_CONNECT, address_bytes(host), target_port)
        code = read_reply(sock)
        assert code == REPLY_SUCCEEDED, f"CONNECT replied {code:#04x}"
    except BaseException:
        sock.close()
        raise
    return sock
