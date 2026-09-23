#!/usr/bin/env bash
# start.sh — build and start the Redis test stack, then seed it via the admin API.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HTTP_PORT=8888
ADMIN_TOKEN="token-value"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[info]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ok]${NC}    $*"; }
die()   { echo -e "${RED}[error]${NC} $*" >&2; exit 1; }

command -v docker >/dev/null || die "docker not found"
docker compose version >/dev/null 2>&1 || die "docker compose (v2 plugin) not found"

cd "$SCRIPT_DIR"

# Create ./data ourselves (owned by the current user) before Docker gets a
# chance to auto-create it as root on first `compose up` - the warpgate
# container runs as uid 1000 and can't write into a root-owned bind mount.
mkdir -p "$SCRIPT_DIR/data"

info "Building the Warpgate image from the current branch (this runs the full cargo + npm build - can take a while the first time)..."
docker compose build

info "Starting the stack..."
docker compose up -d

info "Waiting for Warpgate's HTTPS API on :$HTTP_PORT..."
for _ in $(seq 1 60); do
    if curl -sk "https://localhost:$HTTP_PORT/@warpgate/api/info" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
curl -sk "https://localhost:$HTTP_PORT/@warpgate/api/info" >/dev/null \
    || die "Warpgate never came up - check: docker compose logs warpgate"
ok "Warpgate is up"

info "Seeding test user, role and Redis target..."
ADMIN_TOKEN="$ADMIN_TOKEN" bash "$SCRIPT_DIR/seed.sh" "$HTTP_PORT" "$ADMIN_TOKEN"

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN} Redis test stack is ready!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${CYAN}Admin UI:${NC}    https://localhost:$HTTP_PORT"
echo -e "  ${CYAN}Admin login:${NC} admin / Admin1234!"
echo -e "  ${CYAN}Admin token:${NC} $ADMIN_TOKEN  (X-Warpgate-Token header)"
echo ""
echo -e "  ${CYAN}Redis via warpgate:${NC} redis-cli -p 6379"
echo -e "  ${CYAN}Then:${NC}               AUTH redisuser#my-redis RedisPass123!"
echo ""
echo -e "  Run the smoke test: ${CYAN}./scripts/test-redis-target.sh${NC}"
echo -e "  Logs:               docker compose logs -f warpgate"
echo -e "  Stop:                bash $SCRIPT_DIR/stop.sh"
echo ""
