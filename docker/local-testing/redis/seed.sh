#!/usr/bin/env bash
# seed.sh — seed warpgate with a test user, two Redis targets, and a role via
# the admin API. Idempotent: re-running it after a partial or full previous
# run only creates what's missing.
# Usage: seed.sh <http_port> <admin_token>
set -euo pipefail

HTTP_PORT="${1:-8888}"
TOKEN="${2:-token-value}"
BASE="https://localhost:$HTTP_PORT/@warpgate/admin/api"

TEST_USERNAME="${TEST_USERNAME:-redisuser}"
TEST_PASSWORD="${TEST_PASSWORD:-RedisPass123!}"
TARGET_NAME="${TARGET_NAME:-my-redis}"
AUTH_TARGET_NAME="${AUTH_TARGET_NAME:-my-redis-auth}"
BACKEND_AUTH_USERNAME="${BACKEND_AUTH_USERNAME:-wguser}"
BACKEND_AUTH_PASSWORD="${BACKEND_AUTH_PASSWORD:-wgpassword123}"
ROLE_NAME="test-redis-role"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
skip() { echo -e "  ${YELLOW}↷${NC} $*"; }

api_get()  { curl -sk -H "X-Warpgate-Token: $TOKEN" "$BASE/$1"; }
api_post() { curl -sk -X POST -H "Content-Type: application/json" -H "X-Warpgate-Token: $TOKEN" ${2:+-d "$2"} "$BASE/$1"; }

find_id_by_name() { # <endpoint> <name-field> <name>
    api_get "$1" | python3 -c "
import sys, json
for item in json.load(sys.stdin):
    if item.get('$2') == '$3':
        print(item['id'])
        break
"
}

# ── role ───────────────────────────────────────────────────────────────────────
ROLE_ID=$(find_id_by_name "roles" "name" "$ROLE_NAME")
if [[ -n "$ROLE_ID" ]]; then
    skip "Role '$ROLE_NAME' already exists (id: $ROLE_ID)"
else
    ROLE_ID=$(api_post "roles" "{\"name\":\"$ROLE_NAME\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
    ok "Created role '$ROLE_NAME' (id: $ROLE_ID)"
fi

# ── user + password credential ────────────────────────────────────────────────
USER_ID=$(find_id_by_name "users" "username" "$TEST_USERNAME")
if [[ -n "$USER_ID" ]]; then
    skip "User '$TEST_USERNAME' already exists (id: $USER_ID)"
else
    USER_ID=$(api_post "users" "{\"username\":\"$TEST_USERNAME\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
    ok "Created user '$TEST_USERNAME' (id: $USER_ID)"

    api_post "users/$USER_ID/credentials/passwords" "{\"password\":\"$TEST_PASSWORD\"}" >/dev/null
    ok "Set password credential: $TEST_PASSWORD"
fi

api_post "users/$USER_ID/roles/$ROLE_ID" >/dev/null 2>&1 || true
ok "Assigned $TEST_USERNAME -> $ROLE_NAME"

# ── Redis target, pointing at the redis-target service on the compose network ─
TARGET_ID=$(find_id_by_name "targets" "name" "$TARGET_NAME")
if [[ -n "$TARGET_ID" ]]; then
    skip "Target '$TARGET_NAME' already exists (id: $TARGET_ID)"
else
    TARGET_ID=$(api_post "targets" "{
      \"name\": \"$TARGET_NAME\",
      \"description\": \"Redis test target (docker redis-target:6379)\",
      \"options\": {
        \"kind\": \"Redis\",
        \"host\": \"redis-target\",
        \"port\": 6379,
        \"tls\": { \"mode\": \"Disabled\", \"verify\": true }
      }
    }" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
    ok "Created Redis target '$TARGET_NAME' -> redis-target:6379 (id: $TARGET_ID)"
fi

api_post "targets/$TARGET_ID/roles/$ROLE_ID" >/dev/null 2>&1 || true
ok "Assigned $TARGET_NAME -> $ROLE_NAME"

# ── Second Redis target: backend requires ACL username+password auth ──────────
# Exercises TargetRedisOptions.username/auth - Warpgate authenticating *to*
# the backend, as opposed to the client authenticating to Warpgate above.
AUTH_TARGET_ID=$(find_id_by_name "targets" "name" "$AUTH_TARGET_NAME")
if [[ -n "$AUTH_TARGET_ID" ]]; then
    skip "Target '$AUTH_TARGET_NAME' already exists (id: $AUTH_TARGET_ID)"
else
    AUTH_TARGET_ID=$(api_post "targets" "{
      \"name\": \"$AUTH_TARGET_NAME\",
      \"description\": \"Redis test target requiring backend auth (docker redis-target-auth:6379)\",
      \"options\": {
        \"kind\": \"Redis\",
        \"host\": \"redis-target-auth\",
        \"port\": 6379,
        \"username\": \"$BACKEND_AUTH_USERNAME\",
        \"auth\": { \"kind\": \"Password\", \"password\": \"$BACKEND_AUTH_PASSWORD\" },
        \"tls\": { \"mode\": \"Disabled\", \"verify\": true }
      }
    }" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
    ok "Created Redis target '$AUTH_TARGET_NAME' -> redis-target-auth:6379 as $BACKEND_AUTH_USERNAME (id: $AUTH_TARGET_ID)"
fi

api_post "targets/$AUTH_TARGET_ID/roles/$ROLE_ID" >/dev/null 2>&1 || true
ok "Assigned $AUTH_TARGET_NAME -> $ROLE_NAME"

echo ""
echo -e "${CYAN}Seed complete.${NC}"
echo "  redis-cli -p 6379"
echo "  AUTH $TEST_USERNAME#$TARGET_NAME $TEST_PASSWORD"
echo "  AUTH $TEST_USERNAME#$AUTH_TARGET_NAME $TEST_PASSWORD   (backend requires its own ACL auth)"
