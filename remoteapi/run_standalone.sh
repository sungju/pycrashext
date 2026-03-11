#!/bin/bash

set -euo pipefail

unamestr=$(uname)
versionstr=$(uname -r)
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
web_dir="$script_dir/web"

DRY_RUN=0
CHECK_ONLY=0

normalize_path() {
  local path_to_normalize=$1
  if command -v realpath >/dev/null 2>&1; then
    realpath "$path_to_normalize"
  else
    (cd "$path_to_normalize" && pwd)
  fi
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

usage() {
  echo
  echo "To run this server as a standalone, you need to have"
  echo "the below commands installed."
  echo
  echo "python3, virtualenv, pip"
  echo
  howto_install
  echo
  echo "Options:"
  echo "  --check-only     validate environment and print planned command without executing"
  echo "  --self-check     alias for --check-only"
  echo "  --dry-run        print the entrypoint command without executing"
  echo "  -h, --help      show this help text"
}

howto_install() {
  if [[ "$unamestr" == 'Linux' ]]; then
    if echo "$versionstr" | grep -q "\\.el"; then
      echo "  sudo yum install python3 python3-virtualenv python3-pip"
      echo "  # or: sudo dnf install python3 python3-virtualenv python3-pip"
    else
      echo "Please check your distributor for the below commands"
      echo "  python3"
      echo "  python3-virtualenv (or python3 -m venv)"
      echo "  python3-pip"
    fi
  elif [[ "$unamestr" == 'Darwin' ]]; then
    echo "  brew install python pyenv-virtualenv"
    echo "  python3 -m pip install --upgrade pip"
  fi
}

check_python_tooling() {
  if ! command_exists python3; then
    usage
    echo
    echo "ERROR: python3 is required but not found in PATH"
    exit 1
  fi

  if ! python3 -m pip --version >/dev/null 2>&1; then
    usage
    echo
    echo "ERROR: pip for python3 is not available"
    exit 1
  fi
}

print_effective_config() {
  local source_dir="${RHEL_SOURCE_DIR-<unset>}"
  local python_bin
  python_bin=$(command -v python3)

  echo
  echo "Configuration:"
  echo "  Script directory: $script_dir"
  echo "  RHEL_SOURCE_DIR: $source_dir"
  echo "  python3: $python_bin"
  echo "  web directory: $web_dir"
  echo
}

while (( "$#" )); do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --check-only)
      CHECK_ONLY=1
      ;;
    --self-check)
      CHECK_ONLY=1
      ;;
    --dry-run)
      DRY_RUN=1
      ;;
    *)
      usage
      exit 1
      ;;
  esac
  shift
  done

if [[ -z ${RHEL_SOURCE_DIR-} ]]; then
  echo "RHEL_SOURCE_DIR bash variable should be configured"
  echo "and should point to the source directory."
  echo
  echo "  example)  export RHEL_SOURCE_DIR='/home/dkwon/source/'"
  echo
  echo "The source tree should be something like below."
  echo
  echo "<your_source_dir> -+-- rhel5"
  echo "                   +-- rhel6"
        echo "                   ..."
        echo "                   +-- fedora"
  echo
  echo "The directory doesn't need to have all source repositories."
  echo "It only needs to have the directories you are going to use."
  echo
  exit 1
fi

if [[ ! -d "$RHEL_SOURCE_DIR" ]]; then
  echo "RHEL_SOURCE_DIR does not exist or is not a directory: $RHEL_SOURCE_DIR"
  exit 1
fi

RHEL_SOURCE_DIR=$(normalize_path "$RHEL_SOURCE_DIR")
export RHEL_SOURCE_DIR

check_python_tooling

if [[ ! -d "$web_dir" ]]; then
  echo "Cannot find web directory at $web_dir"
  exit 1
fi

entrypoint_file="$web_dir/entrypoint.sh"
if [[ ! -x "$entrypoint_file" ]]; then
  echo "entrypoint.sh is missing or not executable: $entrypoint_file"
  exit 1
fi

print_effective_config

if (( CHECK_ONLY == 1 )); then
  echo "CHECK-ONLY: validation complete; command plan not executed"
  exit 0
fi

if (( DRY_RUN == 1 )); then
  echo "DRY-RUN: cd \"$web_dir\" && sh ./entrypoint.sh (not executed)"
  exit 0
fi

set_bg() {
        if [[ "$unamestr" == 'Linux' ]]; then
    :
  elif [[ "$unamestr" == 'Darwin' ]]; then
    osascript -e "tell application \"Terminal\" to set background color of window 1 to $1"
  fi
}

if [[ "$unamestr" == 'Darwin' ]]; then
on_exit() {
  set_bg "{65535, 65535, 65535}"
}
trap on_exit EXIT
fi


set_background_color() {
        if [[ "$unamestr" == 'Linux' ]]; then
    :
  elif [[ "$unamestr" == 'Darwin' ]]; then
    set_bg "{65535, 45232, 35980}" 
    #set_bg "{65535, 62451, 63479}"
    #set_bg "{61937, 60395, 47288}"
    #set_bg "{58853, 65278, 65535}"
    #set_bg "{65535, 61166, 54998}"
  fi
}

set_background_color

cd "$web_dir"
sh ./entrypoint.sh
