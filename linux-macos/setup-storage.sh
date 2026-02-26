#!/usr/bin/env bash
# setup-storage.sh (Linux/macOS)
# Native installer (no Docker): MinIO + Nginx HTTPS reverse proxy.

set -euo pipefail

info() { echo "[INFO] $*"; }
warn() { echo "[WARN] $*"; }
err()  { echo "[ERROR] $*"; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

detect_os() {
  case "$(uname -s)" in
    Linux*) echo "linux" ;;
    Darwin*) echo "macos" ;;
    *) echo "unknown" ;;
  esac
}

relaunch_elevated() {
  if [ "${EUID:-$(id -u)}" -eq 0 ]; then return; fi
  exec sudo bash "$0" "$@"
}

normalize_host_input() {
  local raw="${1:-}"
  local v
  if [ -z "${raw// }" ]; then
    echo "localhost"
    return
  fi
  v="$(echo "$raw" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  v="${v#http://}"
  v="${v#https://}"
  v="${v%%/*}"
  v="${v%%:*}"
  v="$(echo "$v" | tr '[:upper:]' '[:lower:]')"
  if ! echo "$v" | grep -Eq '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$'; then
    err "Invalid domain/host: $raw"
    exit 1
  fi
  echo "$v"
}

port_free() {
  local p="$1"
  if has_cmd ss; then
    ! ss -tln 2>/dev/null | grep -qE "[:.]${p}[[:space:]]"
  elif has_cmd lsof; then
    ! lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1
  else
    return 0
  fi
}

pick_port() {
  local p
  for p in "$@"; do
    if port_free "$p"; then echo "$p"; return; fi
  done
  echo ""
}

get_lan_ipv4() {
  local os ip=""
  os="$(detect_os)"
  if [ "$os" = "linux" ] && has_cmd ip; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  elif [ "$os" = "macos" ]; then
    ip="$(ipconfig getifaddr en0 2>/dev/null || true)"
    [ -z "$ip" ] && ip="$(ipconfig getifaddr en1 2>/dev/null || true)"
  fi
  echo "$ip"
}

ensure_prereqs_linux() {
  if has_cmd apt-get; then
    apt-get update -y
    apt-get install -y curl openssl nginx
  elif has_cmd dnf; then
    dnf install -y curl openssl nginx
  elif has_cmd yum; then
    yum install -y curl openssl nginx
  else
    err "Unsupported Linux package manager."
    exit 1
  fi
}

ensure_prereqs_macos() {
  if ! has_cmd brew; then
    err "Homebrew is required on macOS."
    exit 1
  fi
  brew install nginx openssl
}

install_minio_binary() {
  local bin_path="$1"
  info "Installing MinIO binary..."
  curl -fL "https://dl.min.io/server/minio/release/$(uname | tr '[:upper:]' '[:lower:]')-amd64/minio" -o "$bin_path"
  chmod +x "$bin_path"
}

configure_minio_linux() {
  local root="$1" api_port="$2" ui_port="$3"
  local bin="/usr/local/bin/minio"
  local data="${root}/data"
  local envf="/etc/default/locals3-minio"
  mkdir -p "$root" "$data"

  [ -x "$bin" ] || install_minio_binary "$bin"

  cat > "$envf" <<EOF
MINIO_ROOT_USER=admin
MINIO_ROOT_PASSWORD=StrongPassword123
EOF

  cat > /etc/systemd/system/locals3-minio.service <<EOF
[Unit]
Description=Local S3 MinIO
After=network.target

[Service]
EnvironmentFile=$envf
ExecStart=$bin server $data --address :$api_port --console-address :$ui_port
Restart=always
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now locals3-minio
}

configure_minio_macos() {
  local root="$1" api_port="$2" ui_port="$3"
  local bin="/usr/local/bin/minio"
  [ -d /opt/homebrew/bin ] && bin="/opt/homebrew/bin/minio"
  local data="${root}/data"
  local plist="/Library/LaunchDaemons/com.locals3.minio.plist"
  mkdir -p "$root" "$data"
  [ -x "$bin" ] || install_minio_binary "$bin"

  cat > "$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.locals3.minio</string>
  <key>ProgramArguments</key><array>
    <string>$bin</string><string>server</string><string>$data</string>
    <string>--address</string><string>:$api_port</string>
    <string>--console-address</string><string>:$ui_port</string>
  </array>
  <key>EnvironmentVariables</key><dict>
    <key>MINIO_ROOT_USER</key><string>admin</string>
    <key>MINIO_ROOT_PASSWORD</key><string>StrongPassword123</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
EOF

  launchctl bootout system "$plist" >/dev/null 2>&1 || true
  launchctl bootstrap system "$plist"
  launchctl enable system/com.locals3.minio
  launchctl kickstart -k system/com.locals3.minio
}

generate_cert() {
  local cert_dir="$1" domain="$2" lan_ip="$3"
  local crt="$cert_dir/localhost.crt" key="$cert_dir/localhost.key"
  local san="DNS:localhost,IP:127.0.0.1"
  [ "$domain" != "localhost" ] && san="$san,DNS:$domain"
  [ -n "$lan_ip" ] && san="$san,IP:$lan_ip"
  mkdir -p "$cert_dir"
  openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
    -keyout "$key" -out "$crt" \
    -subj "/CN=$domain" -addext "subjectAltName=$san" >/dev/null 2>&1
}

configure_nginx_linux() {
  local domain="$1" https_port="$2" target_port="$3" cert_dir="$4"
  cat > /etc/nginx/conf.d/locals3.conf <<EOF
server {
    listen ${https_port} ssl;
    server_name ${domain} localhost;
    ssl_certificate ${cert_dir}/localhost.crt;
    ssl_certificate_key ${cert_dir}/localhost.key;
    location / {
        proxy_pass http://127.0.0.1:${target_port};
        proxy_http_version 1.1;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF
  nginx -t
  systemctl enable --now nginx
  systemctl restart nginx
}

configure_nginx_macos() {
  local domain="$1" https_port="$2" target_port="$3" cert_dir="$4"
  local prefix
  prefix="$(brew --prefix)"
  local confd="${prefix}/etc/nginx/servers"
  mkdir -p "$confd"
  cat > "${confd}/locals3.conf" <<EOF
server {
    listen ${https_port} ssl;
    server_name ${domain} localhost;
    ssl_certificate ${cert_dir}/localhost.crt;
    ssl_certificate_key ${cert_dir}/localhost.key;
    location / {
        proxy_pass http://127.0.0.1:${target_port};
        proxy_http_version 1.1;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF
  brew services start nginx >/dev/null 2>&1 || true
  nginx -s reload >/dev/null 2>&1 || brew services restart nginx
}

ensure_hosts_entry() {
  local domain="$1" ip="$2"
  [ "$domain" = "localhost" ] && return
  grep -Eq "^[[:space:]]*${ip}[[:space:]]+.*\\b${domain}\\b" /etc/hosts && return
  echo "${ip} ${domain}" >> /etc/hosts
}

trust_cert() {
  local cert="$1" os
  os="$(detect_os)"
  if [ "$os" = "linux" ]; then
    if [ -d /usr/local/share/ca-certificates ] && has_cmd update-ca-certificates; then
      cp "$cert" /usr/local/share/ca-certificates/locals3.crt
      update-ca-certificates >/dev/null 2>&1 || true
    fi
  elif [ "$os" = "macos" ]; then
    security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$cert" >/dev/null 2>&1 || true
  fi
}

main() {
  relaunch_elevated "$@"
  local os root cert_dir https_port api_port ui_port domain lan_ans enable_lan lan_ip
  os="$(detect_os)"
  [ "$os" = "unknown" ] && { err "Unsupported OS."; exit 1; }
  info "===== Local S3 Storage Installer (${os}) - Native Mode ====="

  read -r -p "Enter local domain/URL for HTTPS (default: localhost): " domain
  domain="$(normalize_host_input "${domain:-}")"
  read -r -p "Allow LAN access from other computers? (y/N): " lan_ans
  lan_ans="$(echo "${lan_ans:-n}" | tr '[:upper:]' '[:lower:]')"
  enable_lan=false
  lan_ip=""
  if [ "$lan_ans" = "y" ] || [ "$lan_ans" = "yes" ]; then
    enable_lan=true
    lan_ip="$(get_lan_ipv4)"
  fi

  https_port=443
  if ! port_free 443; then
    warn "Port 443 is busy."
    https_port="$(pick_port 8443 9443 10443)"
    [ -z "$https_port" ] && { err "No free HTTPS port."; exit 1; }
    warn "Using alternate HTTPS port: $https_port"
  fi
  api_port="$(pick_port 9000 19000 29000)"
  ui_port="$(pick_port 9001 19001 29001)"
  [ -z "$api_port" ] && { err "No free API port."; exit 1; }
  [ -z "$ui_port" ] && { err "No free UI port."; exit 1; }

  root="/opt/locals3"
  [ "$os" = "macos" ] && root="/usr/local/locals3"
  cert_dir="${root}/certs"
  mkdir -p "$root" "$cert_dir"

  if [ "$os" = "linux" ]; then
    ensure_prereqs_linux
    configure_minio_linux "$root" "$api_port" "$ui_port"
  else
    ensure_prereqs_macos
    configure_minio_macos "$root" "$api_port" "$ui_port"
  fi

  ensure_hosts_entry "$domain" "127.0.0.1"
  generate_cert "$cert_dir" "$domain" "$lan_ip"
  trust_cert "${cert_dir}/localhost.crt"

  if [ "$os" = "linux" ]; then
    configure_nginx_linux "$domain" "$https_port" "$ui_port" "$cert_dir"
    if [ "$enable_lan" = true ] && has_cmd ufw; then
      ufw allow "${https_port}/tcp" >/dev/null 2>&1 || true
    fi
  else
    configure_nginx_macos "$domain" "$https_port" "$ui_port" "$cert_dir"
  fi

  echo ""
  echo "===== INSTALLATION COMPLETE ====="
  echo "MinIO Console (direct): http://localhost:${ui_port}"
  echo "MinIO API (direct):     http://localhost:${api_port}"
  if [ "$https_port" -eq 443 ]; then
    echo "Proxy URL:              https://${domain}"
  else
    echo "Proxy URL:              https://${domain}:${https_port}"
  fi
  if [ "$enable_lan" = true ] && [ -n "$lan_ip" ]; then
    if [ "$https_port" -eq 443 ]; then
      echo "LAN URL:                https://${lan_ip}"
    else
      echo "LAN URL:                https://${lan_ip}:${https_port}"
    fi
    echo "DNS mapping needed:     ${domain} -> ${lan_ip}"
  fi
  echo ""
  echo "Login:"
  echo "  Username: admin"
  echo "  Password: StrongPassword123"
}

main "$@"

