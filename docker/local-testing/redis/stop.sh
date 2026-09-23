#!/usr/bin/env bash
# stop.sh — tear down the Redis test stack.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GREEN='\033[0;32m'; NC='\033[0m'

cd "$SCRIPT_DIR"
docker compose down --remove-orphans

echo -e "${GREEN}Stack stopped.${NC}"
echo "To fully reset: rm -rf $SCRIPT_DIR/data"
