"""What `wait_port` tells the caller when the wait does not succeed.

Every case here failed silently before: the caller was told the port was up.
On 2026-09-13 that turned `minio/minio` disappearing from Docker Hub into
`Port 1903 is not up` after a 60s timeout, with `docker: pull access denied`
visible only in pytest's captured stderr.
"""

import socket
import subprocess
import threading
import time

import pytest

from .util import alloc_port, wait_port


def test_a_child_that_exits_is_named_rather_than_timed_out():
    """The case the `for_process` argument exists for.

    It raised inside a `try` whose `except` caught `TimeoutExpired`, so the
    exception was swallowed, the wait thread died, and the caller was told the
    port had come up."""
    port = alloc_port()
    child = subprocess.Popen(["sh", "-c", "exit 3"])
    started = time.monotonic()
    with pytest.raises(Exception) as caught:
        wait_port(port, for_process=child, timeout=30)
    # Asserted, or this passes just as well on a plain timeout.
    assert time.monotonic() - started < 10, "waited for the timeout instead"
    assert "exited with code 3" in str(caught.value), caught.value


def test_a_port_that_never_opens_still_times_out():
    port = alloc_port()
    with pytest.raises(Exception, match=f"Port {port} is not up"):
        wait_port(port, timeout=1)


def test_a_listener_that_is_not_serving_yet_is_waited_out():
    """Warpgate's SSH port accepts connections before it serves them, and so
    does a published Docker port. Upstream raised a plain `Exception` there --
    not a `socket.error`, so it escaped the retry loop -- and that raise was
    inert only for as long as a dead waiter counted as a successful one."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def close_twice_then_answer():
        for attempt in range(3):
            conn, _ = server.accept()
            if attempt < 2:
                conn.close()
                continue
            conn.send(b"SSH-2.0-Warpgate\r\n")
            conn.close()

    threading.Thread(target=close_twice_then_answer, daemon=True).start()
    try:
        wait_port(port, timeout=10)
    finally:
        server.close()


def test_a_port_that_only_ever_closes_says_that_when_it_times_out():
    """The same observation, once it is the reason the wait ran out: it
    belongs in the timeout message rather than in a raise that stops the
    wait."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def accept_and_close():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            conn.close()

    threading.Thread(target=accept_and_close, daemon=True).start()
    try:
        with pytest.raises(Exception, match="closes them unanswered"):
            wait_port(port, timeout=3)
    finally:
        server.close()


def test_a_port_that_is_up_is_still_reported_as_up():
    """The control. Without it the four above pass on a `wait_port` that
    always raises."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        wait_port(port, recv=False, timeout=10)
    finally:
        server.close()
