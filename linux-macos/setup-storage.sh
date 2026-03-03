#!/usr/bin/env bash

set -euo pipefail

module_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/modules" && pwd)"
module_files=(core.sh cleanup.sh platform.sh)

for module_file in "${module_files[@]}"; do
  module_path="${module_root}/${module_file}"
  if [ ! -f "${module_path}" ]; then
    echo "[ERROR] Missing required module: ${module_path}"
    echo "[ERROR] This runner now uses local files only. Keep the modules directory next to setup-storage.sh."
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
