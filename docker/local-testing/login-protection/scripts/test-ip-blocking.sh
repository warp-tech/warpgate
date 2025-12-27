#!/bin/bash
# Test script for IP blocking feature
# This script demonstrates how IPs get blocked after failed login attempts

set -e

WARPGATE_URL="${WARPGATE_URL:-https://localhost:8888}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"

echo "=== Login Protection Test: IP Blocking ==="
echo "Target: $WARPGATE_URL"
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
    local expected_status="$3"

    response=$(curl -s -k -w "\n%{http_code}" -X POST \
        "$WARPGATE_URL/@warpgate/api/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"$username\", \"password\": \"$password\"}")

    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    if [[ "$status_code" == "$expected_status" ]]; then
        echo -e "${GREEN}✓${NC} Got expected status $status_code"
    else
        echo -e "${RED}✗${NC} Expected $expected_status, got $status_code"
        echo "  Response: $body"
    fi

    echo "$body"
}

# Function to check security status
check_security_status() {
    echo ""
    echo "=== Security Status ==="
    if [[ -n "$ADMIN_TOKEN" ]]; then
        curl -s -k -X GET \
            "$WARPGATE_URL/@warpgate/admin/api/login-protection/status" \
            -H "Authorization: Bearer $ADMIN_TOKEN" \
            -H "Content-Type: application/json" | python3 -m json.tool 2>/dev/null || echo "(JSON parse failed)"
    else
        echo "(Set ADMIN_TOKEN to view security status)"
    fi
}

# Function to list blocked IPs
list_blocked_ips() {
    echo ""
    echo "=== Blocked IPs ==="
    if [[ -n "$ADMIN_TOKEN" ]]; then
        curl -s -k -X GET \
            "$WARPGATE_URL/@warpgate/admin/api/login-protection/blocked-ips" \
            -H "Authorization: Bearer $ADMIN_TOKEN" \
            -H "Content-Type: application/json" | python3 -m json.tool 2>/dev/null || echo "(JSON parse failed)"
    else
        echo "(Set ADMIN_TOKEN to view blocked IPs)"
    fi
}

# Function to unblock an IP
unblock_ip() {
    local ip="$1"
    echo ""
    echo "=== Unblocking IP: $ip ==="
    if [[ -n "$ADMIN_TOKEN" ]]; then
        curl -s -k -X DELETE \
            "$WARPGATE_URL/@warpgate/admin/api/login-protection/blocked-ips/$ip" \
            -H "Authorization: Bearer $ADMIN_TOKEN"
        echo "Done"
    else
        echo "(Set ADMIN_TOKEN to unblock IPs)"
    fi
}

echo "Step 1: Making failed login attempts to trigger IP block..."
echo "(Config: 3 failed attempts triggers a block)"
echo ""

for i in {1..4}; do
    echo "Attempt $i with wrong password:"
    if [[ $i -le 3 ]]; then
        make_login_attempt "testuser" "wrongpassword$i" "401"
    else
        echo -e "${YELLOW}This attempt should show IP is blocked:${NC}"
        make_login_attempt "testuser" "wrongpassword$i" "401"
    fi
    echo ""
    sleep 0.5
done

check_security_status
list_blocked_ips

echo ""
echo "Step 2: Verify that correct password also fails when IP is blocked..."
make_login_attempt "admin" "correctpassword" "401"

echo ""
echo "=== Test Complete ==="
echo ""
echo "To unblock your IP, run with ADMIN_TOKEN set:"
echo "  ADMIN_TOKEN=<token> $0 --unblock"
echo ""
echo "Or wait for the block to expire (1 minute with test config)"

# Handle --unblock flag
if [[ "$1" == "--unblock" ]] && [[ -n "$ADMIN_TOKEN" ]]; then
    # Try to unblock common local IPs
    unblock_ip "127.0.0.1"
    unblock_ip "::1"
    unblock_ip "172.17.0.1"  # Docker bridge
fi
