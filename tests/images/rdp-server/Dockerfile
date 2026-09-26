# Headless RDP backend for E2E tests. See README.md — this is a CANDIDATE that must be
# validated in CI: Warpgate's helper connects with CredSSP/NLA enabled, and Debian's xrdp
# has limited NLA-server support, so the freerdp-shadow fallback in README.md may be needed.
#
# xrdp + the Xorg backend module (xorgxrdp). No desktop environment: the tests assert that
# a session/framebuffer is produced and relayed, not its contents.
FROM debian:bookworm-slim
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        xrdp xorgxrdp \
    && rm -rf /var/lib/apt/lists/*

# Fixed login the RDP tests authenticate with (the Warpgate target's username/password).
RUN useradd -m -s /bin/bash user && echo 'user:123' | chpasswd

# Keep the X session alive with no DE — a blank Xorg root window is a valid framebuffer.
# (If frames don't flow in CI, give it something to draw: a WM, xterm, or `xsetroot -solid`.)
RUN printf '#!/bin/sh\nexec sleep infinity\n' > /etc/xrdp/startwm.sh \
    && chmod +x /etc/xrdp/startwm.sh

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 3389
ENTRYPOINT ["/entrypoint.sh"]
