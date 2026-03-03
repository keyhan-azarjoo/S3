#!/usr/bin/env bash
# setup-storage.sh (Linux/macOS)
# Native installer (no Docker): MinIO + Nginx HTTPS reverse proxy.

set -euo pipefail

info() { echo "[INFO] $*"; }
warn() { echo "[WARN] $*"; }
err()  { echo "[ERROR] $*"; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

is_ipv4_literal() {
  echo "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
}

is_private_ipv4() {
  local ip="$1"
  case "$ip" in
    10.*|127.*|169.254.*|192.168.*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
    *) return 1 ;;
  esac
}

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
  if ! echo "$v" | grep -Eq '^(([0-9]{1,3}\.){3}[0-9]{1,3}|[a-z0-9]([a-z0-9.-]*[a-z0-9])?)$'; then
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

resolve_https_port_unix() {
  local choice custom_port picked

  if port_free 443; then
    read -r -p "Use HTTPS port 443? (Y/n): " choice
    choice="$(echo "${choice:-y}" | tr '[:upper:]' '[:lower:]')"
    if [ "$choice" = "y" ] || [ "$choice" = "yes" ]; then
      echo "443"
      return
    fi
  else
    warn "Port 443 is busy."
  fi

  echo "Choose HTTPS port option:"
  echo "  1) Auto alternate port (tries: 8443, 9443, 10443)"
  echo "  2) Enter custom port"
  read -r -p "Select option [1/2] (default: 1): " choice

  if [ "${choice:-1}" = "2" ]; then
    while true; do
      read -r -p "Enter custom HTTPS port (1-65535, default: 8443): " custom_port
      custom_port="${custom_port:-8443}"
      if ! echo "$custom_port" | grep -Eq '^[0-9]+$'; then
        warn "Invalid port number: $custom_port"
        continue
      fi
      if [ "$custom_port" -lt 1 ] || [ "$custom_port" -gt 65535 ]; then
        warn "Port must be between 1 and 65535."
        continue
      fi
      if ! port_free "$custom_port"; then
        warn "Port $custom_port is already in use."
        continue
      fi
      echo "$custom_port"
      return
    done
  fi

  picked="$(pick_port 8443 9443 10443)"
  if [ -n "$picked" ]; then
    echo "$picked"
    return
  fi

  err "No free HTTPS port was found in the default range (8443, 9443, 10443)."
  exit 1
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

get_public_ipv4() {
  local candidate
  if [ "$(detect_os)" != "linux" ] || ! has_cmd ip; then
    echo ""
    return
  fi

  while IFS= read -r candidate; do
    candidate="${candidate%%/*}"
    if [ -n "$candidate" ] && ! is_private_ipv4 "$candidate"; then
      echo "$candidate"
      return
    fi
  done < <(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}')

  echo ""
}

ensure_prereqs_linux() {
  if has_cmd apt-get; then
    warn "Ensuring dpkg is in a consistent state..."
    DEBIAN_FRONTEND=noninteractive dpkg --configure -a || true
    if has_cmd systemctl; then
      warn "Ensuring nginx.service is not masked before package install..."
      systemctl unmask nginx >/dev/null 2>&1 || true
    fi
    apt-get update
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
  local os release_name url downloaded=0
  local urls=()
  info "Installing MinIO binary..."
  os="$(uname | tr '[:upper:]' '[:lower:]')"
  release_name="RELEASE.2025-04-22T22-12-26Z"

  if [ "$os" = "linux" ]; then
    urls+=(
      "https://dl.min.io/server/minio/release/linux-amd64/archive/minio.${release_name}"
      "https://dl.min.io/server/minio/release/linux-amd64/archive/minio.RELEASE.2025-01-18T00-31-37Z"
      "https://dl.min.io/server/minio/release/linux-amd64/minio"
    )
  elif [ "$os" = "darwin" ]; then
    urls+=(
      "https://dl.min.io/server/minio/release/darwin-amd64/archive/minio.${release_name}"
      "https://dl.min.io/server/minio/release/darwin-amd64/archive/minio.RELEASE.2025-01-18T00-31-37Z"
      "https://dl.min.io/server/minio/release/darwin-amd64/minio"
    )
  else
    urls+=("https://dl.min.io/server/minio/release/${os}-amd64/minio")
  fi

  for url in "${urls[@]}"; do
    if curl -fL "$url" -o "$bin_path"; then
      downloaded=1
      break
    fi
  done

  if [ "$downloaded" -ne 1 ]; then
    err "Failed to download MinIO binary."
    exit 1
  fi
  chmod +x "$bin_path"
}

configure_minio_linux() {
  local root="$1" api_port="$2" ui_port="$3"
  local bin="/usr/local/bin/minio"
  local data="${root}/data"
  local envf="/etc/default/locals3-minio"
  mkdir -p "$root" "$data"

  install_minio_binary "$bin"

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
  install_minio_binary "$bin"

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
  if [ "$domain" != "localhost" ]; then
    if is_ipv4_literal "$domain"; then
      san="$san,IP:$domain"
    else
      san="$san,DNS:$domain"
    fi
  fi
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
  if has_cmd systemctl; then
    systemctl unmask nginx >/dev/null 2>&1 || true
    systemctl restart nginx >/dev/null 2>&1 || systemctl start nginx >/dev/null 2>&1 || true
  else
    service nginx restart >/dev/null 2>&1 || service nginx start >/dev/null 2>&1 || true
  fi

  if ! port_free "$https_port"; then
    return
  fi

  err "Nginx did not start correctly on port ${https_port}."
  if has_cmd systemctl; then
    warn "nginx.service status:"
    systemctl status nginx --no-pager -l 2>/dev/null || true
  fi
  exit 1
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
  is_ipv4_literal "$domain" && return
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
  local os root cert_dir https_port api_port ui_port domain lan_ans enable_lan lan_ip public_ip use_public_ip proxy_host
  os="$(detect_os)"
  [ "$os" = "unknown" ] && { err "Unsupported OS."; exit 1; }
  info "===== Local S3 Storage Installer (${os}) - Native Mode ====="

  read -r -p "Enter local domain/URL for HTTPS (default: localhost): " domain
  domain="$(normalize_host_input "${domain:-}")"
  if [ "$domain" = "localhost" ]; then
    public_ip="$(get_public_ipv4)"
    if [ -n "$public_ip" ]; then
      read -r -p "Detected public/static IP ${public_ip}. Use it instead of localhost? (Y/n): " use_public_ip
      use_public_ip="$(echo "${use_public_ip:-y}" | tr '[:upper:]' '[:lower:]')"
      if [ "$use_public_ip" = "y" ] || [ "$use_public_ip" = "yes" ]; then
        domain="$public_ip"
      fi
    fi
  fi
  read -r -p "Allow LAN access from other computers? (y/N): " lan_ans
  lan_ans="$(echo "${lan_ans:-n}" | tr '[:upper:]' '[:lower:]')"
  enable_lan=false
  lan_ip=""
  if [ "$lan_ans" = "y" ] || [ "$lan_ans" = "yes" ]; then
    enable_lan=true
    lan_ip="$(get_lan_ipv4)"
  fi

  https_port="$(resolve_https_port_unix)"
  if [ "$https_port" != "443" ]; then
    warn "Using HTTPS port: $https_port"
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
  proxy_host="$domain"
  if [ "$proxy_host" = "localhost" ] && [ -n "$lan_ip" ]; then
    proxy_host="$lan_ip"
  fi
  if [ "$https_port" -eq 443 ]; then
    echo "Proxy URL:              https://${proxy_host}"
  else
    echo "Proxy URL:              https://${proxy_host}:${https_port}"
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

# The main runner now lives in ../setup-storage.sh. This core file only defines
# the reusable install functions.
