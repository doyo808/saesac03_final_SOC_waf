#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/set_custom_rules.sh on|off|status

on     Activate waf/rules/00_custom_rules.conf and reload nginx in the waf container.
off    Activate waf/rules/00_custom_rules.disabled.conf and reload nginx in the waf container.
status Show whether the active runtime file matches the enabled or disabled template.
EOF
}

if [ "${1:-}" = "" ]; then
  usage
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAF_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${WAF_DIR}/.." && pwd)"

ENABLED_TEMPLATE="${WAF_DIR}/rules/00_custom_rules.conf"
DISABLED_TEMPLATE="${WAF_DIR}/rules/00_custom_rules.disabled.conf"
ACTIVE_DIR="${REPO_ROOT}/runtime/modsecurity.d"
ACTIVE_FILE="${ACTIVE_DIR}/00_active_custom_rules.conf"
MODE_ENV_FILE="${WAF_DIR}/modes/current.env"

mkdir -p "${ACTIVE_DIR}"

detect_docker() {
  if docker info >/dev/null 2>&1; then
    DOCKER_BIN="docker"
    USE_SUDO=0
  elif command -v sudo >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
    DOCKER_BIN="docker"
    USE_SUDO=1
  else
    echo "Docker permission denied and sudo unavailable" >&2
    exit 1
  fi
}

docker_run() {
  if [ "${USE_SUDO}" -eq 1 ]; then
    sudo "${DOCKER_BIN}" "$@"
  else
    "${DOCKER_BIN}" "$@"
  fi
}

detect_compose() {
  if [ "${USE_SUDO}" -eq 0 ] && docker compose version >/dev/null 2>&1; then
    COMPOSE_KIND="plugin"
  elif [ "${USE_SUDO}" -eq 1 ] && sudo docker compose version >/dev/null 2>&1; then
    COMPOSE_KIND="plugin"
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_KIND="legacy"
  else
    echo "Neither docker compose nor docker-compose is available" >&2
    exit 1
  fi
}

compose_run() {
  if [ "${COMPOSE_KIND}" = "plugin" ]; then
    docker_run compose "$@"
  elif [ "${USE_SUDO}" -eq 1 ]; then
    sudo docker-compose "$@"
  else
    docker-compose "$@"
  fi
}

print_status() {
  if [ ! -f "${ACTIVE_FILE}" ]; then
    echo "missing: ${ACTIVE_FILE}"
    return 0
  fi

  if cmp -s "${ACTIVE_FILE}" "${ENABLED_TEMPLATE}"; then
    echo "on"
    return 0
  fi

  if cmp -s "${ACTIVE_FILE}" "${DISABLED_TEMPLATE}"; then
    echo "off"
    return 0
  fi

  echo "custom"
}

ensure_container() {
  detect_docker
  detect_compose

  if ! docker_run ps --format '{{.Names}}' | grep -Fxq "waf"; then
    if [ ! -f "${MODE_ENV_FILE}" ]; then
      echo "Mode env file not found: ${MODE_ENV_FILE}" >&2
      exit 1
    fi

    (
      cd "${WAF_DIR}"
      compose_run --env-file "${MODE_ENV_FILE}" up -d
    )
  fi
}

reload_nginx() {
  docker_run exec waf nginx -t
  docker_run exec waf nginx -s reload || docker_run exec waf sh -c 'kill -HUP 1'
}

apply_mode() {
  local template_file="$1"
  local mode_label="$2"
  local backup_file=""

  if [ -f "${ACTIVE_FILE}" ]; then
    backup_file="$(mktemp "${ACTIVE_DIR}/00_active_custom_rules.conf.XXXXXX")"
    cp "${ACTIVE_FILE}" "${backup_file}"
  fi

  cp "${template_file}" "${ACTIVE_FILE}"

  if ensure_container && reload_nginx; then
    if [ -n "${backup_file}" ]; then
      rm -f "${backup_file}"
    fi
    echo "custom rules: ${mode_label}"
    return 0
  fi

  echo "Reload failed, restoring previous active custom rules file" >&2
  if [ -n "${backup_file}" ] && [ -f "${backup_file}" ]; then
    cp "${backup_file}" "${ACTIVE_FILE}"
    rm -f "${backup_file}"
    reload_nginx || true
  else
    rm -f "${ACTIVE_FILE}"
  fi

  exit 1
}

case "${1}" in
  on)
    apply_mode "${ENABLED_TEMPLATE}" "on"
    ;;
  off)
    apply_mode "${DISABLED_TEMPLATE}" "off"
    ;;
  status)
    print_status
    ;;
  *)
    usage
    exit 1
    ;;
esac
