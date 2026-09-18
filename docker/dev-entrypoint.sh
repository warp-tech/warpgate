#!/usr/bin/env bash
#
# Task runner for the review environment. Kept as a script rather than a pile
# of compose `command:` strings so each step is named, and so the frontend
# rebuild — the one you will run dozens of times — is a single short word.
#
# Usage:  docker compose -f docker/docker-compose.dev.yml run --rm dev <task>

set -euo pipefail

FEATURES="mysql,postgres,rdp-openssl-tls"

need_deps() {
    # node_modules is a named volume, so it is empty on first use and survives
    # afterwards. Re-install only when it is missing or the lockfile moved on.
    local stamp=warpgate-web/node_modules/.install-stamp
    if [ ! -f "$stamp" ] || [ warpgate-web/package-lock.json -nt "$stamp" ]; then
        echo "--- installing frontend dependencies ---"
        ( cd warpgate-web && npm ci )
        touch "$stamp"
    fi
}

need_api_clients() {
    # .dockerignore excludes the generated clients and they are not committed,
    # so they have to be generated once inside the container.
    if [ ! -d warpgate-web/src/admin/lib/api-client/dist ]; then
        echo "--- generating OpenAPI clients (first run, slow) ---"
        just openapi
    fi
}

build_ui() {
    local flag="$1"
    need_deps
    need_api_clients
    echo "--- building frontend with VITE_NEW_UI=${flag} ---"
    ( cd warpgate-web && VITE_NEW_UI="${flag}" npm run build )
    echo "--- done. Refresh the browser; no restart needed. ---"
}

case "${1:-serve}" in
    # --- the two you will use constantly ---------------------------------
    ui-new)   build_ui true ;;
    ui-old)   build_ui false ;;

    # --- one-time -------------------------------------------------------
    bootstrap)
        need_deps
        need_api_clients
        build_ui "${VITE_NEW_UI:-true}"
        echo "--- building warpgate (debug, first run is slow) ---"
        cargo build --features "$FEATURES"
        if [ ! -f /data/warpgate.yaml ]; then
            echo "--- first-time setup ---"
            ./target/debug/warpgate --config /data/warpgate.yaml unattended-setup \
                --data-path /data \
                --http-port 8888 \
                --ssh-port 2222 \
                --mysql-port 33306 \
                --external-host localhost
        else
            echo "--- /data/warpgate.yaml exists, skipping setup ---"
        fi
        echo
        echo "Ready. Start it with:"
        echo "  docker compose -f docker/docker-compose.dev.yml up warpgate"
        ;;

    # --- rebuild the backend (only needed for Rust changes) --------------
    backend)
        echo "--- building warpgate (debug, incremental) ---"
        cargo build --features "$FEATURES"
        ;;

    serve)
        # Build if the binary is missing, otherwise start immediately — the
        # point of this environment is not to recompile Rust on every restart.
        if [ ! -x ./target/debug/warpgate ]; then
            echo "--- no debug binary yet, building ---"
            cargo build --features "$FEATURES"
        fi
        exec ./target/debug/warpgate --config /data/warpgate.yaml run
        ;;

    shell)  exec bash ;;
    *)      exec "$@" ;;
esac
