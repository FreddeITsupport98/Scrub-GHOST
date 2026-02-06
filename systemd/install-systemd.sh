#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

ENABLE_TIMER=false
UNINSTALL=false

PREFIX="/usr/local"
LIBEXEC_DIR="$PREFIX/libexec/scrub-ghost"

CONF_DST="/etc/default/scrub-ghost"

usage() {
  cat <<'USAGE'
Usage: sudo ./install-systemd.sh [options]

Installs systemd unit/timer for scrub-ghost, plus a small wrapper under:
  /usr/local/libexec/scrub-ghost/run-systemd

The wrapper reads configuration from:
  /etc/default/scrub-ghost  (or /etc/sysconfig/scrub-ghost)

Options:
  --enable-timer      Enable+start the timer after installing
  --uninstall         Remove installed unit/timer/wrapper
  -h, --help          Show help
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
    --enable-timer)
      ENABLE_TIMER=true
      ;;
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
  rm -f -- /etc/systemd/system/scrub-ghost.service /etc/systemd/system/scrub-ghost.timer 2>/dev/null || true
  rm -rf -- "$LIBEXEC_DIR" 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
  echo "Removed systemd units and wrapper."
  exit 0
fi

# Install wrapper
install -d -m 0755 -- "$LIBEXEC_DIR"
install -m 0755 -- "$SCRIPT_DIR/run-systemd" "$LIBEXEC_DIR/run-systemd"

# Install units
install -m 0644 -- "$SCRIPT_DIR/scrub-ghost.service" /etc/systemd/system/scrub-ghost.service
install -m 0644 -- "$SCRIPT_DIR/scrub-ghost.timer" /etc/systemd/system/scrub-ghost.timer
systemctl daemon-reload

# Install example config if user doesn't already have one
if [[ ! -f /etc/default/scrub-ghost && ! -f /etc/sysconfig/scrub-ghost ]]; then
  install -m 0644 -- "$SCRIPT_DIR/scrub-ghost.conf.example" "$CONF_DST"
  echo "Installed default config: $CONF_DST"
else
  echo "Config already exists; leaving it unchanged."
fi

echo "Installed systemd unit+timer."
if [[ "$ENABLE_TIMER" == true ]]; then
  systemctl enable --now scrub-ghost.timer
  echo "Enabled: scrub-ghost.timer"
else
  echo "To enable the timer: sudo systemctl enable --now scrub-ghost.timer"
fi
