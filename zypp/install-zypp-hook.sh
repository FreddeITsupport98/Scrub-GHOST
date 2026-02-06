#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

UNINSTALL=false

usage() {
  cat <<'USAGE'
Usage: sudo ./install-zypp-hook.sh [options]

Installs the zypp commit hook:
  /etc/zypp/commit.d/50-scrub-ghost

Options:
  --uninstall     Remove the hook
  -h, --help      Show help
USAGE
}

need_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "ERROR: Please run as root (sudo)." >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --uninstall)
      UNINSTALL=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: Unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
  shift
done

need_root

if [[ "$UNINSTALL" == true ]]; then
  rm -f -- /etc/zypp/commit.d/50-scrub-ghost 2>/dev/null || true
  echo "Removed: /etc/zypp/commit.d/50-scrub-ghost"
  exit 0
fi

install -d -m 0755 -- /etc/zypp/commit.d
install -m 0755 -- "$SCRIPT_DIR/50-scrub-ghost" /etc/zypp/commit.d/50-scrub-ghost

echo "Installed: /etc/zypp/commit.d/50-scrub-ghost"
