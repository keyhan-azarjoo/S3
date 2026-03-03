#!/usr/bin/env bash

set -euo pipefail

script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
module_root="${script_root}/modules"
module_files=(core.sh cleanup.sh platform.sh)
remote_module_base="https://raw.githubusercontent.com/keyhan-azarjoo/S3/main/linux-macos/modules"

initialize_module_root() {
  local missing=0
  local refresh_modules=0

  if [ "${script_root}" = "/tmp" ] || [ "${script_root}" = "/var/tmp" ]; then
    refresh_modules=1
  fi

  mkdir -p "${module_root}"

  if [ "${refresh_modules}" -eq 1 ]; then
    rm -f "${module_root}/core.sh" "${module_root}/cleanup.sh" "${module_root}/platform.sh"
  fi

  for module_file in "${module_files[@]}"; do
    module_path="${module_root}/${module_file}"
    if [ "${refresh_modules}" -eq 0 ] && [ -f "${module_path}" ]; then
      continue
    fi

    if [ -f "${module_path}" ]; then
      echo "[INFO] Refreshing module: ${module_file}"
    else
      echo "[INFO] Downloading missing module: ${module_file}"
    fi
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL "${remote_module_base}/${module_file}" -o "${module_path}" || missing=1
    elif command -v wget >/dev/null 2>&1; then
      wget -qO "${module_path}" "${remote_module_base}/${module_file}" || missing=1
    else
      echo "[ERROR] curl or wget is required to download installer modules."
      missing=1
    fi

    if [ "${missing}" -ne 0 ]; then
      break
    fi
  done

  if [ "${missing}" -ne 0 ]; then
    echo "[ERROR] Failed to download required installer modules."
    exit 1
  fi
}

initialize_module_root

for module_file in "${module_files[@]}"; do
  module_path="${module_root}/${module_file}"
  if [ ! -f "${module_path}" ]; then
    echo "[ERROR] Missing required module: ${module_path}"
    echo "[ERROR] Keep the modules directory next to setup-storage.sh or rerun with internet access."
    exit 1
  fi
done

# shellcheck source=modules/core.sh
source "${module_root}/core.sh"
# shellcheck source=modules/cleanup.sh
source "${module_root}/cleanup.sh"
# shellcheck source=modules/platform.sh
source "${module_root}/platform.sh"

run_linux_macos_install "$@"
