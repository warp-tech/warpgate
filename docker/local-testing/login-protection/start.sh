#!/usr/bin/env bash
# start.sh — spin up the login-protection test stack
# Warpgate runs natively (pre-built debug binary); SSH target runs in Docker.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
DATA_DIR="$SCRIPT_DIR/data"
BINARY="$REPO_ROOT/target/debug/warpgate"
ADMIN_PASSWORD="Admin1234!"
ADMIN_TOKEN="token-value"
HTTP_PORT=8888
SSH_PORT=2222
MYSQL_PORT=33306
PG_PORT=55432

# ── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[info]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ok]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC}  $*"; }
die()   { echo -e "${RED}[error]${NC} $*" >&2; exit 1; }

# ── preflight ────────────────────────────────────────────────────────────────
[[ -x "$BINARY" ]] || die "Binary not found at $BINARY — run: cd $REPO_ROOT && unset RUSTUP_TOOLCHAIN && rustup run nightly-2025-10-21-aarch64-apple-darwin cargo build -p warpgate"
command -v docker >/dev/null || die "docker not found"
command -v docker compose >/dev/null 2>&1 || command -v docker-compose >/dev/null || die "docker compose not found"

# ── kill any previous instance ───────────────────────────────────────────────
if [[ -f "$SCRIPT_DIR/.warpgate.pid" ]]; then
  OLD_PID=$(cat "$SCRIPT_DIR/.warpgate.pid")
  if kill -0 "$OLD_PID" 2>/dev/null; then
    info "Stopping previous warpgate (pid $OLD_PID)…"
    kill "$OLD_PID" 2>/dev/null || true
    sleep 1
  fi
  rm -f "$SCRIPT_DIR/.warpgate.pid"
fi

# ── pull + start Docker targets ───────────────────────────────────────────────
info "Starting Docker targets…"
cd "$SCRIPT_DIR"
docker compose pull --quiet 2>/dev/null || true
docker compose up -d
ok "SSH target up on localhost:2223 (sshtestuser / sshtestpassword)"

# ── wait for SSH target to accept connections ─────────────────────────────────
info "Waiting for SSH target…"
for i in $(seq 1 30); do
  if nc -z 127.0.0.1 2223 2>/dev/null; then break; fi
  sleep 1
done
nc -z 127.0.0.1 2223 || die "SSH target never came up on port 2223"
ok "SSH target ready"

# ── prepare data directory ───────────────────────────────────────────────────
info "Preparing data directory: $DATA_DIR"
mkdir -p "$DATA_DIR/ssh-keys"

# Copy test TLS certs
cp "$REPO_ROOT/tests/certs/tls.certificate.pem" "$DATA_DIR/"
cp "$REPO_ROOT/tests/certs/tls.key.pem"         "$DATA_DIR/"

# Copy SSH host keys (warpgate uses these for the SSH listener)
for k in client-ed25519 client-ed25519.pub client-rsa client-rsa.pub host-ed25519 host-ed25519.pub host-rsa; do
  cp "$REPO_ROOT/tests/ssh-keys/wg/$k" "$DATA_DIR/ssh-keys/"
done

# ── unattended-setup (only if not already initialised) ───────────────────────
CONFIG="$DATA_DIR/warpgate.yaml"
if [[ ! -f "$CONFIG" ]]; then
  info "Running unattended-setup…"
  WARPGATE_ADMIN_PASSWORD="$ADMIN_PASSWORD" \
    "$BINARY" --config "$CONFIG" unattended-setup \
      --data-path  "$DATA_DIR" \
      --http-port  "$HTTP_PORT" \
      --ssh-port   "$SSH_PORT" \
      --mysql-port "$MYSQL_PORT" \
      --postgres-port "$PG_PORT" \
      --external-host localhost
  # Accept any SSH host key from targets automatically (test environment only)
  python3 -c "
import yaml, sys
with open('$CONFIG') as f: cfg = yaml.safe_load(f)
cfg.setdefault('ssh', {})['host_key_verification'] = 'auto_accept'
with open('$CONFIG', 'w') as f: yaml.safe_dump(cfg, f)
" 2>/dev/null || \
  sed -i.bak 's/host_key_verification:.*/host_key_verification: auto_accept/' "$CONFIG" || true
  ok "Config generated at $CONFIG"
else
  warn "Config already exists — skipping setup. Delete $DATA_DIR to reset."
fi

# ── start warpgate ────────────────────────────────────────────────────────────
info "Starting warpgate on https://localhost:$HTTP_PORT …"
LOG_FILE="$SCRIPT_DIR/warpgate.log"
WARPGATE_ADMIN_TOKEN="$ADMIN_TOKEN" RUST_LOG="info,warpgate_core::login_protection=debug" \
  "$BINARY" --config "$CONFIG" run --enable-admin-token \
  >"$LOG_FILE" 2>&1 &
WG_PID=$!
echo "$WG_PID" > "$SCRIPT_DIR/.warpgate.pid"
ok "Warpgate started (pid $WG_PID), logs: $LOG_FILE"

# ── wait for warpgate HTTP ────────────────────────────────────────────────────
info "Waiting for warpgate HTTP on :$HTTP_PORT …"
for i in $(seq 1 30); do
  if curl -sk "https://localhost:$HTTP_PORT/@warpgate/api/info" >/dev/null 2>&1; then break; fi
  sleep 1
  if ! kill -0 "$WG_PID" 2>/dev/null; then
    die "Warpgate crashed — check $LOG_FILE"
  fi
done
curl -sk "https://localhost:$HTTP_PORT/@warpgate/api/info" >/dev/null || die "Warpgate HTTP never came up — check $LOG_FILE"
ok "Warpgate HTTP ready"

# ── seed users / targets / roles ─────────────────────────────────────────────
info "Seeding test data…"
bash "$SCRIPT_DIR/seed.sh" "$HTTP_PORT" "$ADMIN_TOKEN"

# ── done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN} Test stack is ready!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${CYAN}Admin UI:${NC}       https://localhost:$HTTP_PORT"
echo -e "  ${CYAN}Admin user:${NC}     admin  /  ${ADMIN_PASSWORD}"
echo -e "  ${CYAN}Admin token:${NC}    ${ADMIN_TOKEN}  (Bearer)"
echo ""
echo -e "  ${CYAN}Test user:${NC}      testuser  /  TestPass123!"
echo -e "  ${CYAN}SSH via warpgate:${NC}  ssh -p $SSH_PORT testuser:my-ssh@localhost"
echo -e "  ${CYAN}SSH password:${NC}   TestPass123!   (warpgate credential)"
echo ""
echo -e "  ${CYAN}SSH target direct:${NC}  ssh -p 2223 sshtestuser@localhost"
echo -e "  ${CYAN}SSH target pass:${NC}    sshtestpassword"
echo ""
echo -e "  Logs:  tail -f $LOG_FILE"
echo -e "  Stop:  bash $SCRIPT_DIR/stop.sh"
echo ""
