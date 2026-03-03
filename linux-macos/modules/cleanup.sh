cleanup_previous_locals3() {
  local root="/opt/locals3"
  [ "$(detect_os)" = "macos" ] && root="/usr/local/locals3"

  if has_cmd systemctl; then
    systemctl stop locals3-minio >/dev/null 2>&1 || true
    systemctl stop nginx >/dev/null 2>&1 || true
  fi

  if [ "$(detect_os)" = "macos" ] && has_cmd brew; then
    brew services stop nginx >/dev/null 2>&1 || true
  fi

  if [ -d "$root" ]; then
    rm -rf "${root}/tmp" >/dev/null 2>&1 || true
  fi
}
