# Login Protection Local Testing

This folder contains a Docker Compose setup for testing the Login Protection (brute-force protection) feature locally.

## Features Tested

- **IP-based rate limiting**: Blocks IPs after N failed login attempts
- **Exponential backoff**: Each subsequent block has a longer duration
- **User account lockout**: Locks user accounts after repeated failures
- **Auto-unlock**: Automatic unlock after lockout duration (configurable)
- **Admin unblock/unlock**: Manual recovery via admin API

## Quick Start

### 1. Build Warpgate Image

From the repository root:

```bash
cd docker/local-testing/login-protection
docker compose build
```

### 2. Start the Stack

```bash
docker compose up -d
```

This starts:
- **Warpgate** on ports 2222 (SSH), 8888 (HTTP/Admin), 33306 (MySQL), 55432 (PostgreSQL)
- **Echo Server** on port 3000 (HTTP target)
- **SSH Target** on port 2223
- **MySQL Target** on port 3306
- **PostgreSQL Target** on port 5432

### 3. Initialize Warpgate

First time setup:

```bash
docker exec -it warpgate-login-protection warpgate setup
```

Or run with admin token enabled:

```bash
docker exec -it warpgate-login-protection warpgate run --enable-admin-token
```

### 4. Access Admin UI

Open https://localhost:8888 and login with the admin credentials you set during setup.

## Test Configuration

The `data/warpgate.yaml` uses aggressive settings for easier testing:

| Setting | Value | Description |
|---------|-------|-------------|
| `ip_rate_limit.max_attempts` | 3 | Block IP after 3 failed attempts |
| `ip_rate_limit.time_window_minutes` | 5 | Count attempts within 5 minutes |
| `ip_rate_limit.base_block_duration_minutes` | 1 | First block: 1 minute |
| `ip_rate_limit.block_duration_multiplier` | 2.0 | Each block doubles |
| `user_lockout.max_attempts` | 5 | Lock user after 5 failed attempts |
| `user_lockout.auto_unlock` | true | Auto-unlock enabled |
| `user_lockout.lockout_duration_minutes` | 2 | Auto-unlock after 2 minutes |

## Running Tests

### Test IP Blocking

```bash
./scripts/test-ip-blocking.sh
```

This makes 4 failed login attempts. After the 3rd attempt, your IP gets blocked.

### Test User Lockout

```bash
./scripts/test-user-lockout.sh
```

This makes 6 failed login attempts for a user. After the 5th attempt, the user gets locked.

### Using Admin API

Get security status:
```bash
curl -k https://localhost:8888/@warpgate/admin/api/login-protection/status \
  -H "Authorization: Bearer <admin-token>"
```

List blocked IPs:
```bash
curl -k https://localhost:8888/@warpgate/admin/api/login-protection/blocked-ips \
  -H "Authorization: Bearer <admin-token>"
```

Unblock an IP:
```bash
curl -k -X DELETE https://localhost:8888/@warpgate/admin/api/login-protection/blocked-ips/127.0.0.1 \
  -H "Authorization: Bearer <admin-token>"
```

List locked users:
```bash
curl -k https://localhost:8888/@warpgate/admin/api/login-protection/locked-users \
  -H "Authorization: Bearer <admin-token>"
```

Unlock a user:
```bash
curl -k -X DELETE https://localhost:8888/@warpgate/admin/api/login-protection/locked-users/admin \
  -H "Authorization: Bearer <admin-token>"
```

## Testing via SSH

Test SSH brute-force protection:

```bash
# Make failed SSH attempts (uses password auth)
for i in {1..4}; do
  sshpass -p "wrongpassword" ssh -o StrictHostKeyChecking=no -p 2222 testuser@localhost echo "test"
done
```

## Testing via MySQL

```bash
# Failed MySQL attempts
for i in {1..4}; do
  mysql -h 127.0.0.1 -P 33306 -u testuser -pwrongpassword 2>/dev/null
done
```

## Viewing Logs

```bash
docker logs -f warpgate-login-protection
```

Look for log entries like:
- `IP blocked ip=X.X.X.X block_count=1 duration_minutes=1`
- `User locked username=admin`
- `Login attempt from blocked IP`

## Cleanup

```bash
docker compose down -v
```

## Troubleshooting

### "IP is blocked but I need to test more"

Wait for the block to expire (1 minute with test config), or use admin API to unblock:

```bash
curl -k -X DELETE https://localhost:8888/@warpgate/admin/api/login-protection/blocked-ips/::1 \
  -H "Authorization: Bearer <token>"
```

### "Cannot connect after multiple tests"

The exponential backoff increases block duration. Reset by:
1. Restart the container: `docker compose restart warpgate`
2. Or delete the database: `rm -rf data/db && docker compose restart warpgate`

### "How do I get an admin token?"

Run warpgate with `--enable-admin-token` flag, then check the logs for the token.
