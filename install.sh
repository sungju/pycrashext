#!/bin/bash

set -euo pipefail

echo "Installing crash extensions running on PyKdump"
echo ""
echo "Please make sure 'PyKdump' is already configured to be loaded"
echo "during crash utility starting."
echo "You can check it by looking for 'extend' command in ~/.crashrc"
echo ""
echo "If you don't have PyKdump extension, you can download it from"
echo "the below link"
echo ""
echo "      Python/CRASH API"
echo "      https://sourceforge.net/projects/pykdump/"
echo ""

CRASHRC="${HOME}/.crashrc"
BASH_PROFILE="${HOME}/.bash_profile"
INSTALL_PATH="$(cd "$(dirname "$0")"; pwd)/source"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

ensure_backup() {
  local target_file="$1"
  if [ -f "$target_file" ]; then
    cp "$target_file" "${target_file}.${TIMESTAMP}.bak"
  fi
}

append_line_if_missing() {
  local target_file="$1"
  local line="$2"
  grep -Fq "$line" "$target_file" 2>/dev/null || echo "$line" >> "$target_file"
}

replace_export() {
  local target_file="$1"
  local key="$2"
  local value="$3"
  local escaped_value
  escaped_value="$(printf "%s" "$value" | sed 's/[&/]/\\&/g')"

  if [ -f "$target_file" ]; then
    if grep -q "^export ${key}=" "$target_file" 2>/dev/null; then
      sed -i "s#^export ${key}=.*#export ${key}=${escaped_value}#" "$target_file"
    else
      append_line_if_missing "$target_file" "export ${key}=${value}"
    fi
  else
    echo "export ${key}=${value}" > "$target_file"
  fi
}

echo "Checking crash command registration for mpykdump plugin..."
if ! grep -Fq "mpykdump" "$CRASHRC" 2>/dev/null; then
  echo "mpykdump is not detected in $CRASHRC"
  echo -n "Please provide mpykdump path [default: /usr/lib64/crash/extensions]> "
  read -r mpykdump_path

  ensure_backup "$CRASHRC"

  if [ -z "${mpykdump_path:-}" ]; then
    mpykdump_path="/usr/lib64/crash/extensions"
  fi

  append_line_if_missing "$CRASHRC" ""
  append_line_if_missing "$CRASHRC" "mach | grep 'MACHINE TYPE' | tail -n 1 | awk '{ printf \"${mpykdump_path}/mpykdump%s.so\\n\", \\$3}' > ${HOME}/arch_mpykdump"
  append_line_if_missing "$CRASHRC" "sf"
  append_line_if_missing "$CRASHRC" "p linux_banner"
  append_line_if_missing "$CRASHRC" "extend < ${HOME}/arch_mpykdump"
  echo "mpykdump registration added to $CRASHRC"
else
  echo "pykdump registration already present in $CRASHRC"
fi

echo
echo "To use 'edis' properly, it's recommended to configure source server"
echo "in another system which has all source repositories and running"
echo "the server by run './run_standalone.sh' or './start_docker.sh' under remoteapi directory"
echo
echo "If it's configured, please provide the server address in the below format."
echo " example) http://<server address>:5000"
echo -n "Please provide address (blank to skip): "
read -r server_addr

if [ -n "${server_addr:-}" ]; then
  ensure_backup "$BASH_PROFILE"
  replace_export "$BASH_PROFILE" "CRASHEXT_SERVER" "$server_addr"
fi

echo -n "Setting PYKDUMPPATH in .bash_profile ..."
PLIB=""
if command -v python3 >/dev/null 2>&1; then
  PLIB=$(python3 -c 'import sys; print(":".join(sys.path).strip())' 2>/dev/null || true)
fi
replace_export "$BASH_PROFILE" "PYKDUMPPATH" "${INSTALL_PATH}:\$PYKDUMPPATH:${PLIB}"
echo " [DONE]"

echo -n "Registering crash extension during crash start ..."
REG_COMMAND="epython ${INSTALL_PATH}/regext.py"
ensure_backup "$CRASHRC"
append_line_if_missing "$CRASHRC" ""
append_line_if_missing "$CRASHRC" "$REG_COMMAND"
echo " [DONE]"

echo ""
echo "All Done"
echo "Please re-login to apply the changes"
