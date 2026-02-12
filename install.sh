#!/usr/bin/env bash
set -euo pipefail

REPO_RAW_BASE="https://raw.githubusercontent.com/Kup1ng/gre-sync/main"

APP_DIR="/opt/gre-sync"
VENV_DIR="/opt/gre-sync/venv"
CFG_DIR="/etc/gre-sync"
CFG_FILE="$CFG_DIR/config.yml"
SERVICE_FILE="/etc/systemd/system/gre-syncd.service"
BIN_WRAPPER="/usr/local/bin/gre"

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "[!] Please run as root: sudo bash"
    exit 1
  fi
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

fetch() {
  local url="$1"
  local out="$2"

  if has_cmd curl; then
    curl -fsSL "$url" -o "$out"
  elif has_cmd wget; then
    wget -qO "$out" "$url"
  else
    echo "[!] Neither curl nor wget found. Installing curl..."
    apt-get update -y
    apt-get install -y curl
    curl -fsSL "$url" -o "$out"
  fi
}

ask() {
  local prompt="$1" default="${2:-}"
  local ans=""
  if [[ -n "$default" ]]; then
    read -r -p "$prompt [$default]: " ans
    ans="${ans:-$default}"
  else
    read -r -p "$prompt: " ans
  fi
  echo "$ans"
}

gen_token() {
  if has_cmd openssl; then
    openssl rand -hex 24
  else
    python3 - <<'PY'
import secrets
print(secrets.token_hex(24))
PY
  fi
}

install_apt_deps() {
  apt-get update -y
  # python3-venv برای ساخت venv لازمه
  apt-get install -y python3 python3-venv python3-pip curl
}

ensure_venv() {
  if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
  fi
  "$VENV_DIR/bin/python" -m pip install --upgrade pip >/dev/null
  "$VENV_DIR/bin/pip" install --no-cache-dir aiohttp pyyaml >/dev/null
}

write_service() {
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=GRE Sync Daemon (healthcheck + coordinated reset)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$VENV_DIR/bin/python $APP_DIR/gre_syncd.py
Restart=always
RestartSec=2
Environment=GRE_SYNC_CONFIG=$CFG_FILE

NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
}

write_wrapper() {
  cat > "$BIN_WRAPPER" <<EOF
#!/usr/bin/env bash
exec $VENV_DIR/bin/python $APP_DIR/gre_cli.py "\$@"
EOF
  chmod +x "$BIN_WRAPPER"
}

render_config() {
  local role="$1" listen="$2" port="$3" token="$4"
  local check_interval="$5" ping_count="$6" ping_timeout="$7" loss_ok="$8"
  local fail_rounds="$9" reset_wait="${10}"

  mkdir -p "$CFG_DIR"
  cat > "$CFG_FILE" <<EOF
role: ${role}
listen: ${listen}
port: ${port}
token: "${token}"

check_interval_sec: ${check_interval}
ping_count: ${ping_count}
ping_timeout_sec: ${ping_timeout}
loss_ok_percent: ${loss_ok}

fail_confirm_rounds: ${fail_rounds}
reset_wait_sec: ${reset_wait}
EOF
}

main() {
  need_root

  echo "=== GRE Sync installer (venv / PEP668-safe) ==="
  echo "Repo: $REPO_RAW_BASE"
  echo

  if ! has_cmd apt-get; then
    echo "[!] This installer currently supports Debian/Ubuntu (apt-get)."
    exit 1
  fi

  echo "[1/7] Installing system deps..."
  install_apt_deps

  echo "[2/7] Creating directories..."
  mkdir -p "$APP_DIR" "$CFG_DIR"

  echo "[3/7] Fetching project files from GitHub..."
  fetch "$REPO_RAW_BASE/gre_syncd.py" "$APP_DIR/gre_syncd.py"
  fetch "$REPO_RAW_BASE/gre_cli.py"  "$APP_DIR/gre_cli.py"
  chmod +x "$APP_DIR/gre_syncd.py" "$APP_DIR/gre_cli.py"

  echo "[4/7] Creating/Updating virtualenv + installing python deps..."
  ensure_venv

  echo
  echo "[5/7] Config setup (interactive)..."

  role="$(ask "Role? (ir/kh)" "ir")"
  if [[ "$role" != "ir" && "$role" != "kh" ]]; then
    echo "[!] Role must be ir or kh"
    exit 1
  fi

  listen="$(ask "API listen address" "0.0.0.0")"
  port="$(ask "API port" "8787")"

  token_default="$(gen_token)"
  token="$(ask "Shared token (must be same on both sides)" "$token_default")"

  check_interval="$(ask "Check interval (sec)" "30")"
  ping_count="$(ask "Ping count per check" "7")"
  ping_timeout="$(ask "Ping timeout per packet (sec)" "1")"
  loss_ok="$(ask "Loss threshold percent (< this = OK)" "20")"

  fail_rounds="$(ask "Fail confirm rounds (consecutive)" "3")"
  reset_wait="$(ask "Reset wait before up (sec)" "300")"

  render_config "$role" "$listen" "$port" "$token" \
                "$check_interval" "$ping_count" "$ping_timeout" "$loss_ok" \
                "$fail_rounds" "$reset_wait"

  echo
  echo "[6/7] Installing systemd service + CLI wrapper..."
  write_service
  write_wrapper

  echo "[7/7] Enabling service..."
  systemctl daemon-reload
  systemctl enable --now gre-syncd

  echo
  echo "=== Done! ==="
  echo "- Config: $CFG_FILE"
  echo "- Service: systemctl status gre-syncd --no-pager"
  echo "- Logs: journalctl -u gre-syncd -f"
  echo "- Menu CLI: gre"
  echo
  echo "Firewall note:"
  echo "- Allow TCP port $port only between your server public IPs."
}

main "$@"
