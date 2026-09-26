#!/bin/bash
# Test script for User Lockout feature
# This script demonstrates how users get locked after failed login attempts

set -e

WARPGATE_URL="${WARPGATE_URL:-https://localhost:8888}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"
TEST_USER="${TEST_USER:-admin}"

echo "=== Login Protection Test: User Lockout ==="
echo "Target: $WARPGATE_URL"
echo "Testing user: $TEST_USER"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to make a login attempt
make_login_attempt() {
    local username="$1"
    local password="$2"

    response=$(curl -s -k -w "\n%{http_code}" -X POST \
        "$WARPGATE_URL/@warpgate/api/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"$username\", \"password\": \"$password\"}")

    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    echo "Status: $status_code"
    echo "Response: $body"
}

# Function to list locked users
list_locked_users() {
    echo ""
    echo "=== Locked Users ==="
    if [[ -n "$ADMIN_TOKEN" ]]; then
        curl -s -k -X GET \
            "$WARPGATE_URL/@warpgate/admin/api/login-protection/locked-users" \
            -H "Authorization: Bearer $ADMIN_TOKEN" \
            -H "Content-Type: application/json" | python3 -m json.tool 2>/dev/null || echo "(JSON parse failed)"
    else
        echo "(Set ADMIN_TOKEN to view locked users)"
    fi
}

# Function to unlock a user
unlock_user() {
    local username="$1"
    echo ""
    echo "=== Unlocking User: $username ==="
    if [[ -n "$ADMIN_TOKEN" ]]; then
        curl -s -k -X DELETE \
            "$WARPGATE_URL/@warpgate/admin/api/login-protection/locked-users/$username" \
            -H "Authorization: Bearer $ADMIN_TOKEN"
        echo "Done"
    else
        echo "(Set ADMIN_TOKEN to unlock users)"
    fi
}

echo "Step 1: Making failed login attempts to trigger user lockout..."
echo "(Config: 5 failed attempts triggers a lockout)"
echo ""

for i in {1..6}; do
    echo "--- Attempt $i with wrong password ---"
    if [[ $i -le 5 ]]; then
        make_login_attempt "$TEST_USER" "wrongpassword$i"
    else
        echo -e "${YELLOW}This attempt should show user is locked:${NC}"
        make_login_attempt "$TEST_USER" "wrongpassword$i"
    fi
    echo ""
    sleep 0.5
done

list_locked_users

echo ""
echo "Step 2: Verify that correct password also fails when user is locked..."
make_login_attempt "$TEST_USER" "correctpassword"

echo ""
echo "=== Test Complete ==="
echo ""
echo "The user will auto-unlock in 2 minutes (per test config)."
echo ""
echo "To unlock immediately, run with ADMIN_TOKEN set:"
echo "  ADMIN_TOKEN=<token> $0 --unlock"

# Handle --unlock flag
if [[ "$1" == "--unlock" ]] && [[ -n "$ADMIN_TOKEN" ]]; then
    unlock_user "$TEST_USER"
fi
