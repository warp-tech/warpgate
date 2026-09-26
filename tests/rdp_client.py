"""Drives Warpgate's native RDP listener with FreeRDP's `xfreerdp` CLI for E2E tests.

RDP is far too large to reimplement (X.224/MCS/GCC/licensing/CredSSP), so unlike the
VNC tests — which hand-roll an RFB client — the RDP tests shell out to FreeRDP.

Warpgate runs its RDP server in TLS mode with a dynamic credential validator (it must
look the user up in the DB, apply the credential policy, and pick the target from the
`user:target` username — none of which IronRDP's pre-loaded NLA credentials can express).
In TLS mode IronRDP validates *after* the handshake, and on rejection Warpgate closes the
socket; FreeRDP then only reports a transport error, indistinguishable from an authorized
session whose backend is unreachable. So the client's exit/output can't tell accept from
reject — instead the tests read Warpgate's verdict server-side (see
`conftest.rdp_session_authorized`): `full_connect` only has to *drive* the connection.
"""

import os
import shutil
import subprocess


def _display_prefix():
    """The `freerdp*-x11` client needs an X display. On headless CI (no `DISPLAY`) wrap it
    in `xvfb-run` to give it a virtual one; a no-op locally where a display already exists."""
    if os.environ.get("DISPLAY"):
        return []
    xvfb_run = shutil.which("xvfb-run")
    return [xvfb_run, "-a"] if xvfb_run else []


def _xfreerdp_bin():
    """FreeRDP 3.x ships `xfreerdp3`, 2.x ships `xfreerdp`. Prefer whichever exists."""
    for name in ("xfreerdp3", "xfreerdp"):
        path = shutil.which(name)
        if path:
            return path
    return None


def have_xfreerdp():
    return _xfreerdp_bin() is not None


def full_connect(host, port, selector, password, timeout):
    """Attempt a full RDP connection to Warpgate's listener, to drive its auth verdict.

    Returns xfreerdp's stdout+stderr (only useful for debugging). Whether Warpgate accepted
    is read server-side, not from this output. `selector` is the `user:target` string.
    """
    binary = _xfreerdp_bin()
    assert binary is not None, "xfreerdp not installed"
    cmd = [
        *_display_prefix(),
        binary,
        f"/v:{host}:{port}",
        f"/u:{selector}",
        f"/p:{password}",
        "/cert:ignore",  # Warpgate's listener uses a self-signed test cert
        "/sec:tls",  # Warpgate terminates TLS (no NLA), so pin the security mode
        "/log-level:INFO",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout)
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired as timed_out:
        output = (timed_out.stdout or b"") + (timed_out.stderr or b"")
    return output.decode("utf-8", "replace")
