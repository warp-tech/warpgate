#!/bin/sh
# Run xrdp + sesman in the foreground (no systemd in a container). xrdp auto-generates
# its TLS key/cert on first start; the Warpgate target uses verify_tls=false to accept it.
#
# NOTE: daemon flags vary across xrdp versions (`-n` / `--nodaemon`). Adjust to the
# packaged version if startup fails — see README.md.
set -e

mkdir -p /var/run/xrdp
rm -f /var/run/xrdp/*.pid 2>/dev/null || true

# RSA keys for RDP-security (harmless when the session negotiates TLS/NLA instead).
[ -f /etc/xrdp/rsakeys.ini ] || xrdp-keygen xrdp auto >/dev/null 2>&1 || true

echo "rdp-server: starting xrdp-sesman + xrdp on :3389" >&2
xrdp-sesman -n &
# Let sesman open its control socket before xrdp dials it.
sleep 1
exec xrdp -n
