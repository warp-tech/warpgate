"""Drives Warpgate's native RDP listener with FreeRDP's `xfreerdp` CLI for E2E tests.

RDP is far too large to reimplement (X.224/MCS/GCC/licensing/CredSSP), so unlike the
VNC tests — which hand-roll an RFB client — the RDP tests shell out to FreeRDP.

Warpgate's RDP serve helper collects the viewer's credentials over NLA (CredSSP),
carrying the `user:target` selector in the username (like the VNC VeNCrypt username).
`+auth-only` runs just the connection/credential handshake and exits — 0 when Warpgate
accepts the credential, non-zero when it rejects it. That's all the auth tests need:
Warpgate signals NLA success as soon as the user is authorized, before it dials the
target, so this asserts the viewer-auth path with no live RDP backend required.
"""

import shutil
import subprocess


def _xfreerdp_bin():
    """FreeRDP 3.x ships `xfreerdp3`, 2.x ships `xfreerdp`. Prefer whichever exists."""
    for name in ("xfreerdp3", "xfreerdp"):
        path = shutil.which(name)
        if path:
            return path
    return None


def have_xfreerdp():
    return _xfreerdp_bin() is not None


def auth_only(host, port, selector, password, timeout):
    """Run an NLA auth-only handshake against Warpgate's RDP listener.

    Returns `(code, output)` where `code` is xfreerdp's exit code (0 = Warpgate accepted
    the credential, non-zero = rejected), or None if xfreerdp hung past `timeout`.
    `output` is xfreerdp's own stdout+stderr, for the test to surface on failure — the
    exit code alone can't tell an auth rejection from the client bailing before the
    handshake. `selector` is the Warpgate `user:target` string, sent as the RDP username.
    """
    binary = _xfreerdp_bin()
    assert binary is not None, "xfreerdp not installed"
    cmd = [
        binary,
        f"/v:{host}:{port}",
        f"/u:{selector}",
        f"/p:{password}",
        "/cert:ignore",  # Warpgate's listener uses a self-signed test cert
        "+auth-only",
        "/log-level:INFO",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as timed_out:
        out = (timed_out.stdout or b"") + (timed_out.stderr or b"")
        return None, _tail(cmd, out)
    return result.returncode, _tail(cmd, result.stdout + result.stderr)


def _tail(cmd, output, limit=4000):
    """Readable command + trailing output, for assertion messages."""
    text = output.decode("utf-8", "replace")
    if len(text) > limit:
        text = "…" + text[-limit:]
    return f"$ {' '.join(cmd)}\n{text}"
