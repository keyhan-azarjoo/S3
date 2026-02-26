#!/usr/bin/env bash
# setup-storage.sh (Linux/macOS)
# HTTPS-first installer for MinIO + Nginx with Docker Compose + fallback.

set -euo pipefail

LOCAL_S3_LABEL="com.locals3.installer=true"

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
  warn "Not running as root. Relaunching with sudo..."
  exec sudo bash "$0" "$@"
}

sanitize_docker_env() {
  local vars=("DOCKER_HOST" "DOCKER_CONTEXT" "DOCKER_TLS_VERIFY" "DOCKER_CERT_PATH" "DOCKER_API_VERSION")
  local name value trim
  for name in "${vars[@]}"; do
    value="${!name:-}"
    if [ -z "${value+x}" ]; then
      continue
    fi
    trim="$(echo "$value" | xargs 2>/dev/null || true)"
    if [ -z "$trim" ] || [ "$trim" = '""' ] || [ "$trim" = "''" ]; then
      warn "$name is malformed ('$value'); clearing it."
    else
      warn "$name is set ('$value'); clearing it so docker context is authoritative."
    fi
    unset "$name" || true
  done
}

ensure_docker_installed() {
  info "Checking Docker installation..."
  if has_cmd docker; then
    info "Docker CLI found."
    return
  fi

  local os
  os="$(detect_os)"
  warn "Docker CLI not found."

  if [ "$os" = "linux" ]; then
    if has_cmd apt-get; then
      info "Installing Docker via apt..."
      apt-get update -y
      apt-get install -y docker.io docker-compose-plugin || apt-get install -y docker.io docker-compose
      systemctl enable docker >/dev/null 2>&1 || true
      systemctl start docker >/dev/null 2>&1 || true
    else
      err "Unsupported Linux package manager for auto-install. Install Docker manually and rerun."
      exit 1
    fi
  elif [ "$os" = "macos" ]; then
    if has_cmd brew; then
      info "Installing Docker Desktop via Homebrew..."
      brew install --cask docker
      warn "Docker Desktop installed. Start it once, then rerun."
      exit 0
    else
      err "Homebrew not found. Install Docker Desktop manually and rerun."
      exit 1
    fi
  else
    err "Unsupported OS. Install Docker manually and rerun."
    exit 1
  fi
}

start_docker() {
  local os
  os="$(detect_os)"
  if [ "$os" = "linux" ]; then
    systemctl start docker >/dev/null 2>&1 || true
  elif [ "$os" = "macos" ]; then
    open -a Docker >/dev/null 2>&1 || true
  fi
}

test_docker_engine() {
  docker info >/dev/null 2>&1
}

wait_docker_engine() {
  info "Checking Docker Engine availability..."
  if test_docker_engine; then
    info "Docker Engine is ready."
    return
  fi

  warn "Docker Engine not reachable. Attempting to start Docker..."
  start_docker

  local max=180 step=5 elapsed=0
  while [ "$elapsed" -lt "$max" ]; do
    sleep "$step"
    elapsed=$((elapsed + step))
    if test_docker_engine; then
      info "Docker Engine is ready."
      return
    fi
  done

  err "Docker Engine is still NOT reachable after waiting."
  exit 1
}

ensure_docker_compose() {
  if docker compose version >/dev/null 2>&1; then
    return
  fi
  warn "docker compose plugin not available."
}

port_free() {
  local p="$1"
  if has_cmd ss; then
    ! ss -tln 2>/dev/null | grep -qE "[:.]${p}[[:space:]]"
  elif has_cmd lsof; then
    ! lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1
  elif has_cmd netstat; then
    ! netstat -tln 2>/dev/null | grep -qE "[:.]${p}[[:space:]]"
  else
    return 0
  fi
}

pick_port() {
  local p
  for p in "$@"; do
    if port_free "$p"; then
      echo "$p"
      return 0
    fi
  done
  echo ""
}

normalize_host_input() {
  local raw="$1"
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
    err "Invalid domain/host input: '$raw'"
    exit 1
  fi
  echo "$v"
}

get_lan_ipv4() {
  local os ip
  os="$(detect_os)"
  if [ "$os" = "linux" ] && has_cmd ip; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  elif [ "$os" = "macos" ]; then
    ip="$(ipconfig getifaddr en0 2>/dev/null || true)"
    [ -z "$ip" ] && ip="$(ipconfig getifaddr en1 2>/dev/null || true)"
  else
    ip=""
  fi
  echo "$ip"
}

ensure_hosts_entry() {
  local domain="$1"
  local ip="$2"
  [ "$domain" = "localhost" ] && return
  grep -Eq "^[[:space:]]*${ip}[[:space:]]+.*\\b${domain}\\b" /etc/hosts && return
  warn "Adding hosts mapping: ${ip} ${domain}"
  echo "${ip} ${domain}" >> /etc/hosts
}

ensure_firewall_port443() {
  local os
  os="$(detect_os)"
  if [ "$os" = "linux" ] && has_cmd ufw; then
    ufw allow 443/tcp >/dev/null 2>&1 || true
  fi
}

ensure_local_tls_cert() {
  local cert_dir="$1"
  local domain="$2"
  local lan_ip="$3"
  local crt="${cert_dir}/localhost.crt"
  local key="${cert_dir}/localhost.key"
  local san="DNS:localhost,IP:127.0.0.1"

  [ "$domain" != "localhost" ] && san="${san},DNS:${domain}"
  [ -n "$lan_ip" ] && san="${san},IP:${lan_ip}"

  mkdir -p "$cert_dir"
  rm -f "$crt" "$key"
  info "Generating self-signed TLS certificate for localhost/${domain}..."
  openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
    -keyout "$key" -out "$crt" \
    -subj "/CN=${domain}" \
    -addext "subjectAltName=${san}" >/dev/null 2>&1

  [ -f "$crt" ] && [ -f "$key" ] || { err "Failed to generate TLS cert."; exit 1; }
}

trust_local_tls_cert() {
  local cert="$1"
  local os
  os="$(detect_os)"
  if [ "$os" = "macos" ]; then
    security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$cert" >/dev/null 2>&1 || \
      warn "Could not auto-trust cert on macOS. Trust it manually."
  elif [ "$os" = "linux" ]; then
    if [ -d /usr/local/share/ca-certificates ] && has_cmd update-ca-certificates; then
      cp "$cert" /usr/local/share/ca-certificates/locals3.crt
      update-ca-certificates >/dev/null 2>&1 || warn "Could not refresh CA store automatically."
    elif has_cmd trust; then
      mkdir -p /etc/pki/ca-trust/source/anchors
      cp "$cert" /etc/pki/ca-trust/source/anchors/locals3.crt
      trust extract-compat >/dev/null 2>&1 || warn "Could not refresh CA store automatically."
    else
      warn "Could not auto-trust cert. Trust it manually on this machine."
    fi
  fi
}

get_script_created_containers() {
  docker --context "$DOCKER_CTX" ps -a \
    --filter "label=${LOCAL_S3_LABEL}" \
    --format "{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}" || true
}

prompt_cleanup_previous_servers() {
  local rows
  rows="$(get_script_created_containers)"
  if [ -z "$rows" ]; then
    # Legacy detection by names
    rows="$(docker --context "$DOCKER_CTX" ps -a --filter "name=^minio$" --format "{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}" || true)"
    rows+=$'\n'"$(docker --context "$DOCKER_CTX" ps -a --filter "name=^nginx$" --format "{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}" || true)"
    rows="$(echo "$rows" | sed '/^$/d')"
  fi
  [ -z "$rows" ] && return

  warn "Found existing S3 containers from previous runs:"
  echo "NAME | IMAGE | STATUS | PORTS"
  echo "$rows"

  local ans
  read -r -p "Delete these previous containers before creating a new server? (Y/n): " ans
  ans="$(echo "${ans:-y}" | tr '[:upper:]' '[:lower:]')"
  if [ "$ans" = "y" ] || [ "$ans" = "yes" ]; then
    echo "$rows" | cut -d'|' -f1 | while read -r cname; do
      [ -n "$cname" ] && docker --context "$DOCKER_CTX" rm -f "$cname" >/dev/null 2>&1 || true
    done
    docker --context "$DOCKER_CTX" network rm storage-net >/dev/null 2>&1 || true
    info "Previous containers were removed."
  else
    warn "Keeping previous containers. This may cause port conflicts."
  fi
}

try_free_443_from_installer() {
  port_free 443 && return
  warn "Port 443 is busy. Checking whether it belongs to previous installer containers..."
  local rows to_remove name
  rows="$(docker --context "$DOCKER_CTX" ps --format "{{.Names}}|{{.Ports}}" || true)"
  to_remove=""
  while IFS='|' read -r name ports; do
    [ -z "$name" ] && continue
    if echo "$ports" | grep -Eq '(^|, )[0-9a-f\.:]*:443->'; then
      to_remove="${to_remove} ${name}"
    fi
  done <<< "$rows"
  [ -z "${to_remove// }" ] && return
  warn "Removing containers to free port 443:${to_remove}"
  for name in $to_remove; do
    docker --context "$DOCKER_CTX" rm -f "$name" >/dev/null 2>&1 || true
  done
  sleep 2
  port_free 443 && info "Port 443 is now free."
}

start_containers_fallback() {
  local ngconf="$1"
  local ngcerts="$2"
  local data="$3"
  local https_port="$4"
  local minio_api="$5"
  local minio_ui="$6"

  warn "Falling back to direct 'docker run' startup (compose unavailable in this environment)."
  docker --context "$DOCKER_CTX" network create storage-net >/dev/null 2>&1 || true
  docker --context "$DOCKER_CTX" rm -f minio nginx >/dev/null 2>&1 || true

  docker --context "$DOCKER_CTX" run -d \
    --name minio \
    --label "$LOCAL_S3_LABEL" \
    --label "com.locals3.role=minio" \
    --network storage-net \
    -e MINIO_ROOT_USER=admin \
    -e MINIO_ROOT_PASSWORD=StrongPassword123 \
    -p "${minio_api}:9000" \
    -p "${minio_ui}:9001" \
    -v "${data}:/data" \
    minio/minio server /data --console-address ":9001" >/dev/null

  docker --context "$DOCKER_CTX" run -d \
    --name nginx \
    --label "$LOCAL_S3_LABEL" \
    --label "com.locals3.role=nginx" \
    --network storage-net \
    -p "${https_port}:443" \
    -v "${ngconf}:/etc/nginx/conf.d:ro" \
    -v "${ngcerts}:/etc/nginx/certs:ro" \
    nginx:latest >/dev/null
}

write_files_and_up() {
  local root project ngconf ngcerts data
  root="$(cd "$(dirname "$0")" && pwd)"
  project="${root}/storage-server"
  ngconf="${project}/nginx/conf"
  ngcerts="${project}/nginx/certs"
  data="${project}/data"
  mkdir -p "$ngconf" "$ngcerts" "$data"

  local domain_input domain lan_ans enable_lan lan_ip
  read -r -p "Enter local domain/URL for HTTPS (default: localhost): " domain_input
  domain="$(normalize_host_input "${domain_input:-}")"
  info "Using local domain: $domain"

  read -r -p "Allow other computers on your network to access this server? (y/N): " lan_ans
  lan_ans="$(echo "${lan_ans:-n}" | tr '[:upper:]' '[:lower:]')"
  enable_lan=false
  lan_ip=""
  if [ "$lan_ans" = "y" ] || [ "$lan_ans" = "yes" ]; then
    enable_lan=true
    lan_ip="$(get_lan_ipv4)"
    [ -n "$lan_ip" ] && info "Detected LAN IP: $lan_ip" || warn "Could not detect LAN IP."
    ensure_firewall_port443
  fi

  sanitize_docker_env
  DOCKER_CTX="$(docker context show 2>/dev/null || true)"
  [ -z "$DOCKER_CTX" ] && DOCKER_CTX="default"
  info "Using Docker context: $DOCKER_CTX"

  prompt_cleanup_previous_servers

  local https_port minio_api minio_ui
  https_port=443
  try_free_443_from_installer
  if ! port_free "$https_port"; then
    warn "Port 443 is already in use."
    local alt_ans
    read -r -p "Use alternate HTTPS port (8443/9443/10443)? (y/N): " alt_ans
    alt_ans="$(echo "${alt_ans:-n}" | tr '[:upper:]' '[:lower:]')"
    if [ "$alt_ans" = "y" ] || [ "$alt_ans" = "yes" ]; then
      https_port="$(pick_port 8443 9443 10443)"
      [ -z "$https_port" ] && { err "No free alternate HTTPS ports."; exit 1; }
      warn "Using alternate HTTPS port: $https_port"
    else
      err "Port 443 is required but currently in use. Free it and rerun."
      exit 1
    fi
  fi

  minio_api="$(pick_port 9000 19000 29000)"
  minio_ui="$(pick_port 9001 19001 29001)"
  [ -z "$minio_api" ] && { err "No free MinIO API port."; exit 1; }
  [ -z "$minio_ui" ] && { err "No free MinIO UI port."; exit 1; }

  info "Using ports:"
  info " - Nginx HTTPS: $https_port"
  info " - MinIO API:  $minio_api"
  info " - MinIO UI:   $minio_ui"
  info "Project folder: $project"

  ensure_hosts_entry "$domain" "127.0.0.1"
  ensure_local_tls_cert "$ngcerts" "$domain" "$lan_ip"
  trust_local_tls_cert "${ngcerts}/localhost.crt"

  local server_names
  server_names="localhost"
  [ "$domain" != "localhost" ] && server_names="${domain} localhost"

  cat > "${project}/docker-compose.yml" <<EOF
services:
  minio:
    image: minio/minio
    container_name: minio
    labels:
      - "com.locals3.installer=true"
      - "com.locals3.role=minio"
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: admin
      MINIO_ROOT_PASSWORD: StrongPassword123
    volumes:
      - ./data:/data
    ports:
      - "${minio_api}:9000"
      - "${minio_ui}:9001"
    restart: unless-stopped

  nginx:
    image: nginx:latest
    container_name: nginx
    labels:
      - "com.locals3.installer=true"
      - "com.locals3.role=nginx"
    ports:
      - "${https_port}:443"
    volumes:
      - ./nginx/conf:/etc/nginx/conf.d:ro
      - ./nginx/certs:/etc/nginx/certs:ro
    depends_on:
      - minio
    restart: unless-stopped
EOF

  cat > "${ngconf}/default.conf" <<EOF
server {
    listen 443 ssl;
    server_name ${server_names};
    ssl_certificate /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;

    location / {
        proxy_pass http://minio:9001;
        proxy_http_version 1.1;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600;
    }
}
EOF

  info "Starting containers..."
  cd "$project"
  docker --context "$DOCKER_CTX" rm -f minio nginx >/dev/null 2>&1 || true
  test_docker_engine || { err "Docker Engine became unavailable."; exit 1; }

  local used_fallback=false
  local compose_out
  set +e
  compose_out="$(docker --context "$DOCKER_CTX" compose up -d 2>&1)"
  local up_exit=$?
  set -e
  if [ "$up_exit" -ne 0 ]; then
    warn "docker compose up failed."
    if echo "$compose_out" | grep -q "invalid proto:"; then
      warn "Detected compose transport error ('invalid proto:')."
      cd "$root"
      start_containers_fallback "$ngconf" "$ngcerts" "$data" "$https_port" "$minio_api" "$minio_ui"
      used_fallback=true
      cd "$project"
    else
      warn "Showing compose logs..."
      docker --context "$DOCKER_CTX" compose logs --no-color --tail 200 2>&1 || true
      exit 1
    fi
  fi

  sleep 3
  local names
  names="$(docker --context "$DOCKER_CTX" ps --format "{{.Names}}" || true)"
  if ! echo "$names" | grep -qx "minio" || ! echo "$names" | grep -qx "nginx"; then
    warn "Containers not running as expected. Logs:"
    if [ "$used_fallback" = true ]; then
      docker --context "$DOCKER_CTX" ps -a --filter "name=minio" --filter "name=nginx" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" || true
      echo "--- minio logs ---"
      docker --context "$DOCKER_CTX" logs --tail 200 minio || true
      echo "--- nginx logs ---"
      docker --context "$DOCKER_CTX" logs --tail 200 nginx || true
    else
      docker --context "$DOCKER_CTX" compose logs --no-color --tail 200 || true
    fi
    exit 1
  fi

  local proxy_url lan_url
  if [ "$https_port" -eq 443 ]; then
    proxy_url="https://${domain}"
  else
    proxy_url="https://${domain}:${https_port}"
  fi
  if [ "$enable_lan" = true ] && [ -n "$lan_ip" ]; then
    if [ "$https_port" -eq 443 ]; then
      lan_url="https://${lan_ip}"
    else
      lan_url="https://${lan_ip}:${https_port}"
    fi
  fi

  echo ""
  echo "===== INSTALLATION COMPLETE ====="
  echo "MinIO Console: http://localhost:${minio_ui}"
  echo "MinIO API:     http://localhost:${minio_api}"
  echo "Proxy URL:     ${proxy_url}"
  [ -n "${lan_url:-}" ] && echo "LAN URL:       ${lan_url}"
  echo ""
  echo "TLS note:"
  echo "  Self-signed cert was generated and trust was attempted on this machine."
  echo ""
  echo "Login:"
  echo "  Username: admin"
  echo "  Password: StrongPassword123"
  echo ""
  echo "For other computers:"
  if [ "$enable_lan" = true ] && [ -n "$lan_ip" ]; then
    [ "$domain" != "localhost" ] && echo "  Add DNS/hosts: ${lan_ip} ${domain}"
    [ "$https_port" -eq 443 ] && echo "  Open: https://${domain}" || echo "  Open: https://${domain}:${https_port}"
    echo "  Cert file to trust on clients (optional): ${ngcerts}/localhost.crt"
  else
    echo "  Enable LAN access on next run if needed."
  fi
}

main() {
  relaunch_elevated "$@"
  info "===== Local S3 Storage Installer (Linux/macOS) ====="
  ensure_docker_installed
  sanitize_docker_env
  wait_docker_engine
  ensure_docker_compose
  write_files_and_up
}

main "$@"

