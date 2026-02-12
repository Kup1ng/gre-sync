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

# Always prompt even with: curl ... | sudo bash
ask() {
  local prompt="$1" default="${2:-}"
  local ans=""

  if [[ -r /dev/tty ]]; then
    if [[ -n "$default" ]]; then
      read -r -p "$prompt [$default]: " ans </dev/tty
      ans="${ans:-$default}"
    else
      read -r -p "$prompt: " ans </dev/tty
    fi
  else
    ans="$default"
    echo "[!] No TTY detected; using default for: $prompt = $ans" >&2
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

# Auto-detect Iran public IP on KH by reading peer of any gre-kh-* interface.
# Example: "... link/gre <local> peer <peer>"
detect_leader_ip_from_gre() {
  ip -o link show 2>/dev/null \
    | awk '
      $0 ~ /: gre-kh-[0-9]+@/ && $0 ~ /link\/gre/ {
        for (i=1; i<=NF; i++) if ($i=="peer") { print $(i+1); exit }
      }
    '
}

render_config_ir() {
  local listen="$1" port="$2" token="$3"
  local check_interval="$4" ping_count="$5" ping_timeout="$6" loss_ok="$7"
  local fail_rounds="$8" reset_wait="$9"
  local http_tries="${10}" http_timeout="${11}" http_backoff_base="${12}" http_backoff_cap="${13}" http_jitter_ratio="${14}"

  mkdir -p "$CFG_DIR"
  cat > "$CFG_FILE" <<EOF
role: ir
listen: ${listen}
port: ${port}
token: "${token}"

check_interval_sec: ${check_interval}
ping_count: ${ping_count}
ping_timeout_sec: ${ping_timeout}
loss_ok_percent: ${loss_ok}

fail_confirm_rounds: ${fail_rounds}
reset_wait_sec: ${reset_wait}

http_tries: ${http_tries}
http_timeout_sec: ${http_timeout}
http_backoff_base: ${http_backoff_base}
http_backoff_cap: ${http_backoff_cap}
http_jitter_ratio: ${http_jitter_ratio}
EOF
}

render_config_kh() {
  local listen="$1" port="$2" token="$3" leader_ip="$4"
  local leader_ping_count="$5" leader_ping_timeout="$6" leader_loss_ok="$7"
  local http_tries="$8" http_timeout="$9" http_backoff_base="${10}" http_backoff_cap="${11}" http_jitter_ratio="${12}"

  mkdir -p "$CFG_DIR"
  cat > "$CFG_FILE" <<EOF
role: kh
listen: ${listen}
port: ${port}
token: "${token}"

leader_public_ip: "${leader_ip}"
leader_ping_count: ${leader_ping_count}
leader_ping_timeout_sec: ${leader_ping_timeout}
leader_loss_ok_percent: ${leader_loss_ok}

http_tries: ${http_tries}
http_timeout_sec: ${http_timeout}
http_backoff_base: ${http_backoff_base}
http_backoff_cap: ${http_backoff_cap}
http_jitter_ratio: ${http_jitter_ratio}
EOF
}

main() {
  need_root

  echo "=== GRE Sync installer (role-aware / venv / PEP668-safe) ==="
  echo "Repo: $REPO_RAW_BASE"
  echo

  if ! has_cmd apt-get; then
    echo "[!] This installer supports Debian/Ubuntu (apt-get)."
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
  port="$(ask "API port (must match both sides)" "8787")"

  token_default="$(gen_token)"
  token="$(ask "Shared token (must be same on both sides)" "$token_default")"

  # HTTP retry knobs (both roles)
  http_tries="$(ask "HTTP tries (peer API retry count)" "3")"
  http_timeout="$(ask "HTTP timeout (sec)" "6")"
  http_backoff_base="$(ask "HTTP backoff base (sec)" "0.7")"
  http_backoff_cap="$(ask "HTTP backoff cap (sec)" "6.0")"
  http_jitter_ratio="$(ask "HTTP jitter ratio" "0.25")"

  if [[ "$role" == "ir" ]]; then
    check_interval="$(ask "GRE check interval (sec)" "30")"
    ping_count="$(ask "Ping count per check" "7")"
    ping_timeout="$(ask "Ping timeout per packet (sec)" "1")"
    loss_ok="$(ask "Loss threshold percent (< this = OK)" "20")"

    fail_rounds="$(ask "Fail confirm rounds (consecutive)" "3")"
    reset_wait="$(ask "Reset wait before UP (sec)" "300")"

    render_config_ir "$listen" "$port" "$token" \
      "$check_interval" "$ping_count" "$ping_timeout" "$loss_ok" \
      "$fail_rounds" "$reset_wait" \
      "$http_tries" "$http_timeout" "$http_backoff_base" "$http_backoff_cap" "$http_jitter_ratio"
  else
    # KH: DO NOT ASK leader IP. Auto-detect from gre-kh-* peer.
    leader_ip="$(detect_leader_ip_from_gre || true)"
    if [[ -z "$leader_ip" ]]; then
      echo "[!] role=kh: could not auto-detect Iran public IP from gre-kh-* interfaces."
      echo "    Please ensure at least one gre-kh-N interface exists before installing."
      echo "    Example check: ip -o link show | grep -E \"gre-kh-[0-9]+\""
      exit 1
    fi
    echo "[i] role=kh: detected leader_public_ip = $leader_ip"

    # These are only for KH control-plane health gating (lightweight)
    leader_ping_count="$(ask "Leader ping count" "3")"
    leader_ping_timeout="$(ask "Leader ping timeout per packet (sec)" "1")"
    leader_loss_ok="$(ask "Leader loss threshold percent (< this = OK)" "20")"

    render_config_kh "$listen" "$port" "$token" "$leader_ip" \
      "$leader_ping_count" "$leader_ping_timeout" "$leader_loss_ok" \
      "$http_tries" "$http_timeout" "$http_backoff_base" "$http_backoff_cap" "$http_jitter_ratio"
  fi

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
