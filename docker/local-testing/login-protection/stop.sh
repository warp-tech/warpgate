#!/usr/bin/env bash
# stop.sh — tear down the login-protection test stack
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GREEN='\033[0;32m'; NC='\033[0m'

# Kill warpgate
if [[ -f "$SCRIPT_DIR/.warpgate.pid" ]]; then
  PID=$(cat "$SCRIPT_DIR/.warpgate.pid")
  if kill -0 "$PID" 2>/dev/null; then
    echo "Stopping warpgate (pid $PID)…"
    kill "$PID"
    sleep 1
  fi
  rm -f "$SCRIPT_DIR/.warpgate.pid"
fi

# Stop Docker containers
cd "$SCRIPT_DIR"
docker compose down --remove-orphans 2>/dev/null || true

echo -e "${GREEN}Stack stopped.${NC}"
echo "To fully reset: rm -rf $SCRIPT_DIR/data"
