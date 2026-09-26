#!/usr/bin/env bash
# seed.sh — seed warpgate with test user, SSH target, and role via admin API
# Usage: seed.sh <http_port> <admin_token>
set -euo pipefail

HTTP_PORT="${1:-8888}"
TOKEN="${2:-token-value}"
BASE="https://localhost:$HTTP_PORT/@warpgate/admin/api"
CURL="curl -sk -H 'Content-Type: application/json' -H 'Authorization: Bearer $TOKEN'"

# ── colour helpers ────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
skip() { echo -e "  ${YELLOW}↷${NC} $*"; }

api_get()  { curl -sk -H "X-Warpgate-Token: $TOKEN" "$BASE/$1"; }
api_post() { curl -sk -X POST -H "Content-Type: application/json" -H "X-Warpgate-Token: $TOKEN" -d "$2" "$BASE/$1"; }
api_del()  { curl -sk -X DELETE -H "X-Warpgate-Token: $TOKEN" "$BASE/$1"; }

# ── helpers ───────────────────────────────────────────────────────────────────
jq_or_python() {
  if command -v jq >/dev/null 2>&1; then
    echo "$1" | jq -r "$2"
  else
    echo "$1" | python3 -c "import sys,json; print(json.load(sys.stdin)$3)"
  fi
}

# ── check if already seeded ───────────────────────────────────────────────────
EXISTING_USER=$(api_get "users" | python3 -c "
import sys, json
users = json.load(sys.stdin)
for u in users:
    if u.get('username') == 'testuser':
        print(u['id'])
        break
" 2>/dev/null || echo "")

if [[ -n "$EXISTING_USER" ]]; then
  skip "testuser already exists (id: $EXISTING_USER) — skipping seed"
  exit 0
fi

# ── create role ───────────────────────────────────────────────────────────────
ROLE_RESP=$(api_post "roles" '{"name":"test-ssh-role"}')
ROLE_ID=$(echo "$ROLE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
ok "Created role 'test-ssh-role' (id: $ROLE_ID)"

# ── create user ───────────────────────────────────────────────────────────────
USER_RESP=$(api_post "users" '{"username":"testuser"}')
USER_ID=$(echo "$USER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
ok "Created user 'testuser' (id: $USER_ID)"

# ── add password credential ───────────────────────────────────────────────────
api_post "users/$USER_ID/credentials/passwords" '{"password":"TestPass123!"}' >/dev/null
ok "Set password credential: TestPass123!"

# ── assign user to role ───────────────────────────────────────────────────────
api_post "users/$USER_ID/roles" "{\"id\":\"$ROLE_ID\"}" >/dev/null
ok "Assigned testuser → test-ssh-role"

# ── create SSH target ─────────────────────────────────────────────────────────
TARGET_RESP=$(api_post "targets" '{
  "name": "my-ssh",
  "options": {
    "kind": "Ssh",
    "host": "localhost",
    "port": 2223,
    "username": "sshtestuser",
    "auth": {
      "kind": "Password",
      "password": "sshtestpassword"
    }
  }
}')
TARGET_ID=$(echo "$TARGET_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
ok "Created SSH target 'my-ssh' → localhost:2223 (id: $TARGET_ID)"

# ── assign target to role ─────────────────────────────────────────────────────
api_post "targets/$TARGET_ID/roles" "{\"id\":\"$ROLE_ID\"}" >/dev/null
ok "Assigned my-ssh → test-ssh-role"

echo ""
echo -e "${CYAN}Seed complete.${NC}"
