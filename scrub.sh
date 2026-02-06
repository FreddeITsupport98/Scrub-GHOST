#!/usr/bin/env bash

# Safer BLS entry scrubber for openSUSE (Tumbleweed)
# - Defaults to dry-run
# - When forced, moves ghost entries to a backup directory (no hard delete)
# - Avoids false positives when the entry already uses /boot/… paths
# - Protects Snapper snapshot entries when the snapshot subvolume exists

set -euo pipefail
IFS=$'\n\t'

ENTRIES_DIR=""
ENTRIES_DIR_SET=false

# Root directory used to resolve BLS paths like /vmlinuz-… or /EFI/…
# If not provided, it will be derived from ENTRIES_DIR (two dirs up).
BOOT_DIR=""
BOOT_DIR_SET=false

DRY_RUN=true
DELETE_MODE="backup" # "backup" or "delete"
BACKUP_DIR=""        # if empty, a timestamped dir under ENTRIES_DIR will be used
REBUILD_GRUB=false
GRUB_CFG="/boot/grub2/grub.cfg"

usage() {
  cat <<'USAGE'
Usage: scrub.sh [options]

Scans Boot Loader Specification (BLS) entries under /boot/loader/entries and
identifies "ghost" entries that reference a missing kernel image.

Default is DRY-RUN (no changes).

Options:
  --dry-run              Scan only (default)
  --force                Apply changes (moves ghost entries to backup dir)
  --delete               Permanently delete ghost entries (implies --force)
  --backup-dir DIR       Where to move ghost entries when using --force
  --entries-dir DIR      BLS entries directory (default: auto-detect)
  --boot-dir DIR         Root dir used to resolve BLS paths (default: derived from entries dir)
  --rebuild-grub         Run grub2-mkconfig after changes
  --grub-cfg PATH        Output path for grub2-mkconfig (default: /boot/grub2/grub.cfg)
  -h, --help             Show this help

Examples:
  sudo ./scrub.sh
  sudo ./scrub.sh --force
  sudo ./scrub.sh --force --backup-dir /root/bls-backup
  sudo ./scrub.sh --delete
USAGE
}

log() { printf '%s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*"; }
err() { printf 'ERROR: %s\n' "$*" >&2; }

resolve_boot_path() {
  # Resolves a BLS path to a concrete path on disk.
  # BLS commonly uses paths like /vmlinuz-… or /EFI/… (relative to $BOOT_DIR).
  # Some setups already include /boot/….
  local p="$1"

  if [[ -z "$p" ]]; then
    return 1
  fi

  if [[ "$p" == /* ]]; then
    if [[ "$p" == "${BOOT_DIR%/}/"* ]]; then
      printf '%s\n' "$p"
    else
      printf '%s\n' "${BOOT_DIR%/}$p"
    fi
  else
    printf '%s\n' "${BOOT_DIR%/}/$p"
  fi
}

snapshot_dir_from_entry() {
  # Extracts a Snapper snapshot dir like /.snapshots/123/snapshot (if present).
  # Returns the first match on stdout.
  grep -Eo '/\.snapshots/[0-9]+/snapshot' "$1" 2>/dev/null | head -n 1 || true
}

# Root check
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  err "Please run as root (sudo)."
  exit 1
fi

# Argument parsing
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=true
      ;;
    --force)
      DRY_RUN=false
      ;;
    --delete)
      DRY_RUN=false
      DELETE_MODE="delete"
      ;;
    --backup-dir)
      shift
      BACKUP_DIR="${1:-}"
      ;;
    --entries-dir)
      shift
      ENTRIES_DIR="${1:-}"
      ENTRIES_DIR_SET=true
      ;;
    --boot-dir)
      shift
      BOOT_DIR="${1:-}"
      BOOT_DIR_SET=true
      ;;
    --rebuild-grub)
      REBUILD_GRUB=true
      ;;
    --grub-cfg)
      shift
      GRUB_CFG="${1:-}"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      err "Unknown argument: $1"
      usage
      exit 2
      ;;
  esac
  shift
done

if [[ "$ENTRIES_DIR_SET" == false ]]; then
  # openSUSE commonly mounts the ESP at /boot/efi (sd-boot) and Fedora-like setups use /boot.
  for d in /boot/loader/entries /boot/efi/loader/entries /efi/loader/entries; do
    if [[ -d "$d" ]]; then
      ENTRIES_DIR="$d"
      break
    fi
  done
fi

if [[ -z "$ENTRIES_DIR" || ! -d "$ENTRIES_DIR" ]]; then
  err "Entries dir not found. Tried: /boot/loader/entries, /boot/efi/loader/entries, /efi/loader/entries"
  err "(or pass --entries-dir DIR)"
  exit 1
fi

if [[ "$BOOT_DIR_SET" == false ]]; then
  BOOT_DIR="$(dirname "$(dirname "$ENTRIES_DIR")")"
fi

if [[ ! -d "$BOOT_DIR" ]]; then
  warn "Boot root dir not found: $BOOT_DIR (path checks may be wrong)"
fi

log "========================================"
log " Checking for Ghost BLS Entries"
log " Entries: $ENTRIES_DIR"
log " Boot dir: $BOOT_DIR"
log " Mode: $( [[ "$DRY_RUN" == true ]] && echo DRY-RUN || echo APPLY ) (${DELETE_MODE})"
log "========================================"

ok_count=0
ghost_count=0
protected_count=0
moved_or_deleted_count=0
skipped_count=0

ensure_backup_dir() {
  if [[ "$DELETE_MODE" == "delete" ]]; then
    return 0
  fi

  if [[ -z "$BACKUP_DIR" ]]; then
    local ts
    ts="$(date +%Y%m%d-%H%M%S)"
    BACKUP_DIR="$ENTRIES_DIR/.scrub-ghost-backup-$ts"
  fi

  mkdir -p -- "$BACKUP_DIR"
}

for entry in "$ENTRIES_DIR"/*.conf; do
  [[ -e "$entry" ]] || continue

  # Pull first linux/linuxefi path.
  kernel_path="$(
    awk '
      $1 ~ /^linux(efi)?$/ {
        print $2;
        exit
      }
    ' "$entry" 2>/dev/null || true
  )"

  if [[ -z "$kernel_path" ]]; then
    warn "Skipping (no linux/linuxefi line): $(basename -- "$entry")"
    skipped_count=$((skipped_count + 1))
    continue
  fi

  kernel_full="$(resolve_boot_path "$kernel_path" || true)"
  if [[ -z "$kernel_full" ]]; then
    warn "Skipping (could not resolve kernel path): $(basename -- "$entry")"
    skipped_count=$((skipped_count + 1))
    continue
  fi

  # Snapshot protection: if the entry references a snapshot and it exists, never touch it.
  snap_dir="$(snapshot_dir_from_entry "$entry")"
  snap_present=false
  if [[ -n "$snap_dir" && -d "$snap_dir" ]]; then
    snap_present=true
  fi

  if [[ -e "$kernel_full" ]]; then
    log "[OK]   $(basename -- "$entry")"
    ok_count=$((ok_count + 1))
    continue
  fi

  # Kernel missing -> likely a ghost entry.
  ghost_count=$((ghost_count + 1))

  log ""
  log "[GHOST] $(basename -- "$entry")"
  log "        linux:   $kernel_path"
  log "        lookup:  $kernel_full"

  if [[ "$snap_present" == true ]]; then
    log "        note:    references existing snapshot ($snap_dir)"
    log "        action:  SKIP (protected snapshot entry)"
    protected_count=$((protected_count + 1))
    continue
  fi

  if [[ "$DRY_RUN" == true ]]; then
    if [[ "$DELETE_MODE" == "delete" ]]; then
      log "        action:  (dry-run) would DELETE"
    else
      log "        action:  (dry-run) would MOVE to backup"
    fi
    continue
  fi

  if [[ "$DELETE_MODE" == "delete" ]]; then
    log "        action:  deleting entry file"
    rm -f -- "$entry"
    moved_or_deleted_count=$((moved_or_deleted_count + 1))
  else
    ensure_backup_dir
    log "        action:  moving entry file -> $BACKUP_DIR"
    mv -- "$entry" "$BACKUP_DIR/"
    moved_or_deleted_count=$((moved_or_deleted_count + 1))
  fi

done

log ""
log "========================================"
log " Summary"
log "   OK entries:           $ok_count"
log "   Ghost entries:        $ghost_count"
log "   Protected snapshots:  $protected_count"
log "   Skipped (malformed):  $skipped_count"
if [[ "$DRY_RUN" == false ]]; then
  log "   Changed:              $moved_or_deleted_count"
  if [[ "$DELETE_MODE" != "delete" && -n "$BACKUP_DIR" ]]; then
    log "   Backup dir:           $BACKUP_DIR"
  fi
else
  log "   Changed:              0 (dry-run)"
  log ""
  log "To apply safely (move ghosts to backup):"
  log "  sudo bash $0 --force"
  log "To permanently delete ghosts:"
  log "  sudo bash $0 --delete"
fi
log "========================================"

if [[ "$DRY_RUN" == false && "$REBUILD_GRUB" == true ]]; then
  log ""
  if command -v grub2-mkconfig >/dev/null 2>&1; then
    log "Rebuilding GRUB menu: $GRUB_CFG"
    grub2-mkconfig -o "$GRUB_CFG"
    log "Done."
  else
    warn "--rebuild-grub requested, but grub2-mkconfig not found"
  fi
fi
