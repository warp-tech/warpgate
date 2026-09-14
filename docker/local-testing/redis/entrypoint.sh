#!/bin/sh
# entrypoint.sh — bootstrap Warpgate on first boot, then run it.
#
# WARPGATE_CONFIG is set by the image (docker/Dockerfile) to /data/warpgate.yaml.
# /data is the bind-mounted ./data folder, so this only runs once per stack.
set -e

if [ ! -f "$WARPGATE_CONFIG" ]; then
    echo "[entrypoint] no config at $WARPGATE_CONFIG - running unattended-setup"
    warpgate unattended-setup \
        --data-path /data \
        --http-port 8888 \
        --ssh-port 2222 \
        --redis-port 6379 \
        --external-host localhost \
        --record-sessions \
        --host-key-verification auto-accept
fi

exec warpgate run --enable-admin-token
