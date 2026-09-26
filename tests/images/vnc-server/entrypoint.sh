#!/bin/sh
# Minimal headless VNC backend for E2E tests: a TigerVNC X server on a fixed
# 800x600 framebuffer.
#
# Security type is configurable via env so the same image serves both the
# viewer-auth tests (no backend auth) and the target-auth test:
#   VNC_SECURITY=None    (default) — no backend authentication
#   VNC_SECURITY=VncAuth           — require the VncAuth password in VNC_PASSWORD
set -e

SECURITY="${VNC_SECURITY:-None}"
echo "vnc-server: SecurityTypes=$SECURITY geometry=${VNC_GEOMETRY:-800x600}" >&2
set -- Xtigervnc :0 \
    -geometry "${VNC_GEOMETRY:-800x600}" \
    -depth 24 \
    -rfbport 5900 \
    -localhost no \
    -AlwaysShared \
    -SecurityTypes "$SECURITY"

if [ "$SECURITY" = "VncAuth" ]; then
    mkdir -p /root/.vnc
    # TigerVNC ships the password tool as `tigervncpasswd`; fall back to `vncpasswd`.
    PW_TOOL="$(command -v tigervncpasswd || command -v vncpasswd || true)"
    [ -n "$PW_TOOL" ] || { echo "no vncpasswd tool found" >&2; exit 1; }
    echo "${VNC_PASSWORD:-123}" | "$PW_TOOL" -f > /root/.vnc/passwd
    chmod 600 /root/.vnc/passwd
    set -- "$@" -rfbauth /root/.vnc/passwd
fi

exec "$@"
