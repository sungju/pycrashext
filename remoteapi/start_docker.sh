#!/bin/bash
#
# remoteapi docker starting script
#
# Written by Daniel Sungju Kwon
# dkwon@redhat.com
#

set -euo pipefail

unamestr=$(uname)

COMPOSE_CMD=()
COMPOSE_NAME=""
BUILD_BEFORE_START=0
DRY_RUN=0
CHECK_ONLY=0
compose_started=0

require_non_empty_var() {
  local var_name=$1
  if [[ -z ${!var_name-} ]]; then
    echo "ERROR: $var_name is empty or unset"
    return 1
  fi
}

normalize_path() {
  local path_to_normalize=$1
  if command -v realpath >/dev/null 2>&1; then
    realpath "$path_to_normalize"
  else
    (cd "$path_to_normalize" && pwd)
  fi
}

usage() {
        echo "RHEL_SOURCE_DIR needs to be configured properly"
        echo "    This should point to the directory that contains"
        echo "    all the source code and the path should be in the"
        echo "    rhelX such as rhel5, rhel6, rhel7, etc"
        echo ""
        echo "You may want to put it in ~/.bash_profile with something like below"
        echo "export RHEL_SOURCE_DIR=/home/dkwon/source/"
        echo ""
        echo "Options:"
        echo "  -b, --build      Build the docker image before starting"
        echo "  --check-only     validate environment and print planned command without launching containers"
        echo "  --self-check     Alias for --check-only"
        echo "  --dry-run        Print docker-compose commands without executing"
        echo
}

build_docker_image() {
  run_compose build
}

while (( "$#" )); do
  case "$1" in
    -h|--help) # help
      usage
      exit 0
      ;;
    -b|--build) # Build the docker before start
      BUILD_BEFORE_START=1
      ;;
    --check-only) # check and exit
      CHECK_ONLY=1
      ;;
    --self-check) # explicit alias for check-only
      CHECK_ONLY=1
      ;;
    --dry-run) # print commands only
      DRY_RUN=1
      ;;
    *) # unknown option
      usage
      exit 1
      ;;
  esac
  shift
  done


error_docker_start_commands() {
  echo
  echo "  systemctl start docker.service"
  echo "  systemctl enable docker.service"
  echo
}


error_docker_commands() {
  echo
  echo "WARNING: docker and compose are required"
  echo "  to run this tool."
  echo
  echo "Install Docker and compose from your distro packages or https://docs.docker.com/engine/install/"
  echo
  echo "RHEL provided packages (example):"
  echo
  echo "  sudo yum-config-manager --enable rhel-7-server-extras-rpms"
  echo "  sudo yum install docker docker-client docker-common -y"
  echo
  echo "Upstream docker packages:"
  echo "  https://docs.docker.com/engine/install/"
  echo "  https://docs.docker.com/compose/install/"
  echo
  error_docker_start_commands
}

run_compose() {
  if (( DRY_RUN == 1 )); then
    echo "DRY-RUN: ${COMPOSE_CMD[*]} $*"
    return 0
  fi
  "${COMPOSE_CMD[@]}" "$@"
}

print_effective_config() {
  local insights_value="${INSIGHTS_RULES-<unset>}"
  local port_value="${PYCRASHEXT_PORT-5000}"
  echo
  echo "Configuration:"
  echo "  RHEL_SOURCE_DIR=$RHEL_SOURCE_DIR"
  echo "  COMPOSE_COMMAND=$COMPOSE_NAME"
  echo "  INSIGHTS_RULES=$insights_value"
  echo "  PYCRASHEXT_PORT=$port_value"
  echo
}

restore_docker_state() {
  local rc=$?
  if (( compose_started == 1 )); then
    run_compose down --rmi all --remove-orphans || true
  fi

  if [[ -n ${OLD_INSIGHTS_RULES_SAVED-} ]]; then
    INSIGHTS_RULES=$OLD_INSIGHTS_RULES_SAVED
    export INSIGHTS_RULES
  fi
  return $rc
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

if command_exists docker; then
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD=(docker compose)
    COMPOSE_NAME='docker compose'
  elif command_exists docker-compose; then
    COMPOSE_CMD=(docker-compose)
    COMPOSE_NAME='docker-compose'
  fi
fi

if ((${#COMPOSE_CMD[@]} == 0)); then
  error_docker_commands
  exit 2
fi

if (( CHECK_ONLY == 0 )); then
  if ! docker info >/dev/null 2>&1; then
    echo "ERROR: docker daemon is not reachable. Start Docker and retry."
    echo
    error_docker_start_commands
    exit 3
  fi
fi

check_docker_fs() {
  if [[ "$unamestr" != 'Linux' ]]; then
    return 0
  fi

  local mount_point
  local fstype=""
  local d_ftype=""

  if ! mount_point=$(df -P /var/lib/docker 2>/dev/null | awk 'NR==2 { print $NF }'); then
    return 0
  fi

  if [[ -z "$mount_point" ]]; then
    return 0
  fi

  fstype=$(findmnt -n -o FSTYPE --target "$mount_point" 2>/dev/null || mount | awk -v m=" $mount_point " '$0 ~ m { print $5 }' | tail -n 1)
  if [[ "$fstype" != "xfs" ]]; then
    return 0
  fi

  if ! command_exists xfs_info; then
    echo "WARNING: xfs_info not installed; unable to verify d_ftype for $mount_point"
    return 0
  fi

  d_ftype=$(xfs_info "$mount_point" 2>/dev/null | grep 'ftype=1')
  if [[ -z "$d_ftype" ]]; then
    echo
    echo "WARNING: /var/lib/docker is mounted as xfs but d_ftype=1 was not detected."
    echo "This configuration can cause overlayfs issues on RHEL"
    echo
    echo "You can check ftype by running:"
    echo "  xfs_info /var/lib/docker"
    echo
    exit 4
  fi
}

if ! require_non_empty_var RHEL_SOURCE_DIR; then
  usage
  exit 5
fi

if [[ ! -d "$RHEL_SOURCE_DIR" ]]; then
  echo "ERROR: RHEL_SOURCE_DIR does not exist or is not a directory: $RHEL_SOURCE_DIR"
  exit 6
fi

RHEL_SOURCE_DIR=$(normalize_path "$RHEL_SOURCE_DIR")
export RHEL_SOURCE_DIR

check_docker_fs

if [[ -n ${INSIGHTS_RULES-} ]]; then
  OLD_INSIGHTS_RULES_SAVED=$INSIGHTS_RULES
fi

if [[ -d "./insights-rules" ]]; then
  insight_rules=()
  for dentry in ./insights-rules/*; do
    if [[ ! -d "$dentry" ]]; then
      continue
    fi
    bname=$(basename -- "$dentry")
    if [[ "$bname" == "*" ]]; then
      continue
    fi
    insight_rules+=("/insights-rules/$bname")
  done

  if ((${#insight_rules[@]} > 0)); then
    INSIGHTS_RULES="$(IFS=:; printf '%s' "${insight_rules[*]}")"
  else
    INSIGHTS_RULES=""
  fi
  export INSIGHTS_RULES
fi

print_effective_config

if (( CHECK_ONLY == 1 )); then
  echo "CHECK-ONLY: validation complete, command plan not executed"
  exit 0
fi

if (( DRY_RUN == 1 )); then
  if (( BUILD_BEFORE_START == 1 )); then
    build_docker_image
  fi
  run_compose up crashext
  exit 0
fi

trap restore_docker_state EXIT INT TERM

if (( BUILD_BEFORE_START == 1 )); then
  build_docker_image
fi

run_compose up crashext
compose_started=1
sleep 1
