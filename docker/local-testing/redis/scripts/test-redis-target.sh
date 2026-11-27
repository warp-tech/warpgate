#!/usr/bin/env bash
# test-redis-target.sh — smoke-test the Redis target through Warpgate's Redis
# listener (RESP proxy on :6379), using redis-cli as the client would.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REDIS_PORT="${REDIS_PORT:-6379}"
WG_USER="${TEST_USERNAME:-redisuser}"
WG_PASSWORD="${TEST_PASSWORD:-RedisPass123!}"
TARGET_NAME="${TARGET_NAME:-my-redis}"
AUTH_TARGET_NAME="${AUTH_TARGET_NAME:-my-redis-auth}"
SELECTOR="$WG_USER#$TARGET_NAME"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
pass() { echo -e "  ${GREEN}✓${NC} $*"; }
fail() { echo -e "  ${RED}✗${NC} $*"; exit 1; }

# Prefer a local redis-cli if there's one on PATH; otherwise reuse the
# redis-tools already inside the redis-target container, reaching Warpgate
# over the compose network by its container name.
if command -v redis-cli >/dev/null 2>&1; then
    redis_cli() { redis-cli -p "$REDIS_PORT" "$@"; }
else
    redis_cli() { (cd "$SCRIPT_DIR" && docker compose exec -T redis-target redis-cli -h wg-redis-poc -p "$REDIS_PORT" "$@"); }
fi

echo -e "${CYAN}== Authenticated round-trip through Warpgate ==${NC}"
KEY="wgtest:$$"
OUT=$(redis_cli <<EOF
AUTH $SELECTOR $WG_PASSWORD
PING
SET $KEY hello-from-warpgate
GET $KEY
DEL $KEY
EOF
)
echo "$OUT"

echo "$OUT" | grep -qx "PONG" || fail "PING did not return PONG"
pass "PING -> PONG"

echo "$OUT" | grep -qx "hello-from-warpgate" || fail "GET did not return the value SET moments earlier"
pass "SET/GET round-tripped through the proxy"

echo ""
echo -e "${CYAN}== Round-trip through a backend that requires its own username+password ==${NC}"
AUTH_SELECTOR="$WG_USER#$AUTH_TARGET_NAME"
AUTH_KEY="wgtest:auth:$$"
AUTH_OUT=$(redis_cli <<EOF
AUTH $AUTH_SELECTOR $WG_PASSWORD
PING
SET $AUTH_KEY hello-from-authed-backend
GET $AUTH_KEY
DEL $AUTH_KEY
EOF
)
echo "$AUTH_OUT"

echo "$AUTH_OUT" | grep -qx "PONG" || fail "PING against the auth-required backend did not return PONG (did Warpgate authenticate to redis-target-auth correctly?)"
pass "PING -> PONG through the ACL-protected backend"

echo "$AUTH_OUT" | grep -qx "hello-from-authed-backend" || fail "GET did not return the value SET moments earlier on the auth-required backend"
pass "SET/GET round-tripped through Warpgate's backend username+password auth"

echo ""
echo -e "${CYAN}== Wrong credentials are rejected ==${NC}"
BAD=$(redis_cli AUTH "$WG_USER#$TARGET_NAME" "wrong-password" 2>&1 || true)
echo "$BAD" | grep -qi "WRONGPASS\|ERR" || fail "expected an auth error for a wrong password, got: $BAD"
pass "Wrong password rejected ($BAD)"

echo ""
echo -e "${CYAN}== Unknown target is rejected ==${NC}"
BAD=$(redis_cli AUTH "$WG_USER#no-such-target" "$WG_PASSWORD" 2>&1 || true)
echo "$BAD" | grep -qi "ERR\|WRONGPASS" || fail "expected an error for an unknown target, got: $BAD"
pass "Unknown target rejected ($BAD)"

echo ""
echo -e "${GREEN}All Redis target checks passed.${NC}"
