#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/scrub.sh"

PREFIX="/usr/local"
BIN_NAME="scrub-ghost"
INSTALL_SYSTEMD=false
ENABLE_TIMER=false
INSTALL_ZYPP=false
UNINSTALL=false

# Defaults: if integrations already exist on the system, refresh them on install
UPDATE_SYSTEMD_IF_PRESENT=true
UPDATE_ZYPP_IF_PRESENT=true
REMOVE_SYSTEMD=false
REMOVE_ZYPP=false

usage() {
  cat <<'USAGE'
Usage: sudo ./install.sh [options]

Installs scrub.sh as a system command (scrub-ghost) and optionally installs
systemd units and/or a zypper (zypp) commit hook.

Options:
  --prefix DIR          Install prefix (default: /usr/local)
  --bin-name NAME       Installed command name (default: scrub-ghost)
  --systemd                   Install systemd service+timer via systemd/install-systemd.sh
  --enable-timer              Enable+start the timer (implies --systemd)
  --zypp-hook                 Install zypp commit hook via zypp/install-zypp-hook.sh
  --remove-systemd            Remove systemd unit/timer/wrapper (no effect on command)
  --remove-zypp               Remove zypp hook (no effect on command)
  --no-update-systemd         Do not refresh systemd integration even if present
  --no-update-zypp            Do not refresh zypp hook even if present
  --uninstall                 Remove installed command and integration bits
  -h, --help                  Show help

Examples:
  sudo ./install.sh
  sudo ./install.sh --systemd --enable-timer
  sudo ./install.sh --zypp-hook
  sudo ./install.sh --uninstall
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
    --prefix)
      shift
      PREFIX="${1:-}"
      ;;
    --bin-name)
      shift
      BIN_NAME="${1:-}"
      ;;
    --systemd)
      INSTALL_SYSTEMD=true
      ;;
    --enable-timer)
      INSTALL_SYSTEMD=true
      ENABLE_TIMER=true
      ;;
    --zypp-hook)
      INSTALL_ZYPP=true
      ;;
    --remove-systemd)
      REMOVE_SYSTEMD=true
      ;;
    --remove-zypp)
      REMOVE_ZYPP=true
      ;;
    --no-update-systemd)
      UPDATE_SYSTEMD_IF_PRESENT=false
      ;;
    --no-update-zypp)
      UPDATE_ZYPP_IF_PRESENT=false
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

if [[ ! -f "$SRC" ]]; then
  echo "ERROR: Source script not found: $SRC" >&2
  exit 1
fi

BIN_DIR="$PREFIX/bin"
DEST="$BIN_DIR/$BIN_NAME"

if [[ "$UNINSTALL" == true ]]; then
  echo "Uninstalling $DEST"
  rm -f -- "$DEST" 2>/dev/null || true

  # Remove integration bits too (best-effort)
  rm -f -- /etc/systemd/system/scrub-ghost.service /etc/systemd/system/scrub-ghost.timer 2>/dev/null || true
  rm -rf -- /usr/local/libexec/scrub-ghost 2>/dev/null || true
  rm -f -- /etc/zypp/commit.d/50-scrub-ghost 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true

  echo "Done."
  exit 0
fi

mkdir -p -- "$BIN_DIR"
install -m 0755 -- "$SRC" "$DEST"

echo "Installed: $DEST"

# Remove integrations if requested
if [[ "$REMOVE_SYSTEMD" == true ]]; then
  if [[ -x "$SCRIPT_DIR/systemd/install-systemd.sh" ]]; then
    "$SCRIPT_DIR/systemd/install-systemd.sh" --uninstall || true
  else
    echo "WARN: systemd/install-systemd.sh not found; removing known unit paths directly" >&2
    rm -f -- /etc/systemd/system/scrub-ghost.service /etc/systemd/system/scrub-ghost.timer 2>/dev/null || true
    rm -rf -- /usr/local/libexec/scrub-ghost 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
  fi
fi

if [[ "$REMOVE_ZYPP" == true ]]; then
  if [[ -x "$SCRIPT_DIR/zypp/install-zypp-hook.sh" ]]; then
    "$SCRIPT_DIR/zypp/install-zypp-hook.sh" --uninstall || true
  else
    rm -f -- /etc/zypp/commit.d/50-scrub-ghost 2>/dev/null || true
  fi
fi

# Install integrations if explicitly requested
if [[ "$INSTALL_SYSTEMD" == true ]]; then
  if [[ -x "$SCRIPT_DIR/systemd/install-systemd.sh" ]]; then
    args=()
    [[ "$ENABLE_TIMER" == true ]] && args+=("--enable-timer")
    "$SCRIPT_DIR/systemd/install-systemd.sh" "${args[@]}"
  else
    echo "ERROR: systemd/install-systemd.sh not found or not executable" >&2
    exit 1
  fi
fi

if [[ "$INSTALL_ZYPP" == true ]]; then
  if [[ -x "$SCRIPT_DIR/zypp/install-zypp-hook.sh" ]]; then
    "$SCRIPT_DIR/zypp/install-zypp-hook.sh"
  else
    echo "ERROR: zypp/install-zypp-hook.sh not found or not executable" >&2
    exit 1
  fi
fi

# Update integrations if they are already present (default)
if [[ "$UPDATE_SYSTEMD_IF_PRESENT" == true && "$INSTALL_SYSTEMD" == false && "$REMOVE_SYSTEMD" == false ]]; then
  if [[ -f /etc/systemd/system/scrub-ghost.service || -d /usr/local/libexec/scrub-ghost ]]; then
    if [[ -x "$SCRIPT_DIR/systemd/install-systemd.sh" ]]; then
      "$SCRIPT_DIR/systemd/install-systemd.sh" || true
      echo "Updated existing systemd integration."
    fi
  fi
fi

if [[ "$UPDATE_ZYPP_IF_PRESENT" == true && "$INSTALL_ZYPP" == false && "$REMOVE_ZYPP" == false ]]; then
  if [[ -f /etc/zypp/commit.d/50-scrub-ghost ]]; then
    if [[ -x "$SCRIPT_DIR/zypp/install-zypp-hook.sh" ]]; then
      "$SCRIPT_DIR/zypp/install-zypp-hook.sh" || true
      echo "Updated existing zypp hook."
    fi
  fi
fi

echo "Verify: sudo $BIN_NAME --help"
