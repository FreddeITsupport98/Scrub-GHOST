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
BACKUP_DIR=""        # if empty, a timestamped dir under BACKUP_ROOT will be used
REBUILD_GRUB=false
GRUB_CFG="/boot/grub2/grub.cfg"

# Backup root (never inside ENTRIES_DIR by default)
BACKUP_ROOT="/var/backups/scrub-ghost"

# Mode
ACTION="scan"  # scan | list-backups | restore
RESTORE_FROM=""

# Verification / pruning knobs
VERIFY_SNAPSHOTS=true
VERIFY_KERNEL_MODULES=true
PRUNE_STALE_SNAPSHOTS=false
PRUNE_UNINSTALLED_KERNELS=false
CONFIRM_PRUNE_UNINSTALLED=false

# Backup knobs (enabled automatically when applying changes)
AUTO_BACKUP=true
AUTO_SNAPPER_BACKUP=true
SNAPPER_BACKUP_ID=""

# Filled at runtime (if snapper exists)
declare -A SNAPSHOT_NUM_SET
SNAPPER_AVAILABLE=false

usage() {
  cat <<'USAGE'
Usage: scrub.sh [options]

Scans Boot Loader Specification (BLS) entries under /boot/loader/entries and
identifies "ghost" entries that reference a missing kernel image.

Default is DRY-RUN (no changes).

Options:
  --dry-run              Scan only (default)
  --force                Apply changes (moves ghost/stale entries to backup dir)
  --delete               Permanently delete ghost entries (implies --force)
  --backup-dir DIR       Backup directory to move pruned entries into (default: auto)
  --backup-root DIR      Root directory used for automatic backups (default: /var/backups/scrub-ghost)
  --entries-dir DIR      BLS entries directory (default: auto-detect)
  --boot-dir DIR         Root dir used to resolve BLS paths (default: derived from entries dir)
  --rebuild-grub         Run grub2-mkconfig after changes
  --grub-cfg PATH        Output path for grub2-mkconfig (default: /boot/grub2/grub.cfg)

Easy restore:
  --list-backups         List backup folders under backup root
  --restore-latest       Restore BLS entries from the latest backup (replaces current *.conf)
  --restore-from DIR     Restore BLS entries from a specific backup directory

Backup (runs automatically on --force/--delete):
  --no-backup             Do not create a filesystem backup copy of entries before changes
  --no-snapper-backup     Do not create a snapper snapshot before changes

Verification / pruning (all safe by default; pruning requires --force):
  --no-verify-snapshots   Don't verify snapper snapshot numbers
  --no-verify-modules     Don't verify kernel modules dirs for the entry's kernel version
  --prune-stale-snapshots Move/delete snapper entries whose snapshot number doesn't exist
  --prune-uninstalled     Move/delete entries whose kernel modules dir is missing (requires --confirm-uninstalled)
  --confirm-uninstalled   Required extra safety flag to actually prune uninstalled-kernel entries

  -h, --help             Show this help

Examples:
  sudo ./scrub.sh
  sudo ./scrub.sh --force --prune-stale-snapshots
  sudo ./scrub.sh --list-backups
  sudo ./scrub.sh --restore-latest
  sudo ./scrub.sh --restore-from /var/backups/scrub-ghost/bls-entries-YYYYMMDD-HHMMSS
USAGE
}

log() { printf '%s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*"; }
err() { printf 'ERROR: %s\n' "$*" >&2; }

ts_now() { date +%Y%m%d-%H%M%S; }

latest_backup_dir() {
  # Prefer explicit latest symlink; otherwise pick newest matching directory.
  if [[ -d "$BACKUP_ROOT/latest" ]]; then
    printf '%s\n' "$BACKUP_ROOT/latest"
    return 0
  fi

  ls -1dt "$BACKUP_ROOT"/bls-entries-* 2>/dev/null | head -n 1 || true
}

list_backups() {
  mkdir -p -- "$BACKUP_ROOT" 2>/dev/null || true
  if ! ls -1d "$BACKUP_ROOT"/bls-entries-* >/dev/null 2>&1; then
    log "No backups found under: $BACKUP_ROOT"
    exit 0
  fi

  log "Backups under: $BACKUP_ROOT"
  ls -1dt "$BACKUP_ROOT"/bls-entries-* 2>/dev/null | while IFS= read -r d; do
    local when
    when="$(basename -- "$d")"
    local count
    count="$(ls -1 "$d"/full/*.conf 2>/dev/null | wc -l || true)"
    if [[ -f "$d/manifest.txt" ]]; then
      log "- $d (full entries: $count)"
    else
      log "- $d (full entries: $count; no manifest)"
    fi
  done
}

restore_entries_from_backup() {
  local src="$1"
  if [[ -z "$src" ]]; then
    err "restore: missing source directory"
    exit 2
  fi
  if [[ ! -d "$src" ]]; then
    err "restore: backup dir not found: $src"
    exit 1
  fi
  if ! compgen -G "$src/full/*.conf" >/dev/null; then
    err "restore: no 'full/*.conf' found in: $src"
    exit 1
  fi

  # Backup current entries before replacing.
  local ts
  ts="$(ts_now)"
  local pre_dir="$BACKUP_ROOT/restore-pre-$ts"
  mkdir -p -- "$pre_dir"

  if compgen -G "$ENTRIES_DIR/*.conf" >/dev/null; then
    cp -a -- "$ENTRIES_DIR"/*.conf "$pre_dir/" 2>/dev/null || cp -p -- "$ENTRIES_DIR"/*.conf "$pre_dir/"
  fi

  # Replace entries set (clear then copy).
  rm -f -- "$ENTRIES_DIR"/*.conf 2>/dev/null || true
  cp -a -- "$src"/full/*.conf "$ENTRIES_DIR/" 2>/dev/null || cp -p -- "$src"/full/*.conf "$ENTRIES_DIR/"

  log "Restore complete."
  log "- Restored from: $src"
  log "- Previous entries saved to: $pre_dir"
}

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

snapshot_num_from_entry() {
  # Returns the snapshot number (digits only) if the entry references /.snapshots/<n>/snapshot
  local n
  n="$(grep -Eo '/\.snapshots/[0-9]+/snapshot' "$1" 2>/dev/null | head -n 1 | grep -Eo '[0-9]+' || true)"
  [[ -n "$n" ]] && printf '%s\n' "$n" || true
}

kernel_version_from_linux_path() {
  # openSUSE sdbootutil typically uses:
  #   linux /opensuse-tumbleweed/<KVER>/linux-<hash>
  # Return <KVER> if detectable.
  local p="$1"
  p="${p#/}"
  local distro_seg="${p%%/*}"
  local rest="${p#*/}"

  # Needs at least 2 segments
  if [[ "$rest" == "$p" ]]; then
    return 1
  fi

  local kver="${rest%%/*}"
  if [[ -n "$kver" && "$kver" != "$rest" ]]; then
    printf '%s\n' "$kver"
  else
    return 1
  fi
}

modules_dir_exists_for_kver() {
  local kver="$1"
  [[ -n "$kver" ]] || return 1
  [[ -d "/lib/modules/$kver" || -d "/usr/lib/modules/$kver" ]]
}

load_snapper_snapshot_set() {
  if command -v snapper >/dev/null 2>&1; then
    SNAPPER_AVAILABLE=true
    while IFS= read -r raw; do
      raw="${raw//[^0-9]/}"
      [[ -n "$raw" ]] && SNAPSHOT_NUM_SET["$raw"]=1
    done < <(snapper --no-dbus list 2>/dev/null | awk '/^[[:space:]]*[0-9]+/ {print $1}')
  fi
}

snapshot_exists() {
  # True if snapshot exists either on-disk or in snapper list output.
  local n="$1"
  [[ -n "$n" ]] || return 1

  if [[ -d "/.snapshots/$n/snapshot" ]]; then
    return 0
  fi

  if [[ "$SNAPPER_AVAILABLE" == true && -n "${SNAPSHOT_NUM_SET[$n]+x}" ]]; then
    return 0
  fi

  return 1
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
    --backup-root)
      shift
      BACKUP_ROOT="${1:-}"
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

    --list-backups)
      ACTION="list-backups"
      ;;
    --restore-latest)
      ACTION="restore"
      RESTORE_FROM="__LATEST__"
      ;;
    --restore-from)
      ACTION="restore"
      shift
      RESTORE_FROM="${1:-}"
      ;;

    --no-backup)
      AUTO_BACKUP=false
      ;;
    --no-snapper-backup)
      AUTO_SNAPPER_BACKUP=false
      ;;

    --no-verify-snapshots)
      VERIFY_SNAPSHOTS=false
      ;;
    --no-verify-modules)
      VERIFY_KERNEL_MODULES=false
      ;;
    --prune-stale-snapshots)
      PRUNE_STALE_SNAPSHOTS=true
      ;;
    --prune-uninstalled)
      PRUNE_UNINSTALLED_KERNELS=true
      ;;
    --confirm-uninstalled)
      CONFIRM_PRUNE_UNINSTALLED=true
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

# Handle non-scan actions early (after we know ENTRIES_DIR).
if [[ "$ACTION" == "list-backups" ]]; then
  list_backups
  exit 0
fi

if [[ "$ACTION" == "restore" ]]; then
  mkdir -p -- "$BACKUP_ROOT" 2>/dev/null || true

  if [[ "$RESTORE_FROM" == "__LATEST__" ]]; then
    RESTORE_FROM="$(latest_backup_dir)"
  fi

  if [[ -z "$RESTORE_FROM" ]]; then
    err "restore: no backup found (use --list-backups)"
    exit 1
  fi

  restore_entries_from_backup "$RESTORE_FROM"
  exit 0
fi

if [[ "$BOOT_DIR_SET" == false ]]; then
  BOOT_DIR="$(dirname "$(dirname "$ENTRIES_DIR")")"
fi

if [[ ! -d "$BOOT_DIR" ]]; then
  warn "Boot root dir not found: $BOOT_DIR (path checks may be wrong)"
fi

if [[ "$VERIFY_SNAPSHOTS" == true ]]; then
  load_snapper_snapshot_set
fi

log "========================================"
log " Checking for Ghost BLS Entries"
log " Entries: $ENTRIES_DIR"
log " Boot dir: $BOOT_DIR"
log " Mode: $( [[ "$DRY_RUN" == true ]] && echo DRY-RUN || echo APPLY ) (${DELETE_MODE})"
log " Auto backup:      $AUTO_BACKUP"
log " Auto snapper:     $AUTO_SNAPPER_BACKUP"
log " Verify snapshots: $VERIFY_SNAPSHOTS (snapper: $SNAPPER_AVAILABLE)"
log " Verify modules:   $VERIFY_KERNEL_MODULES"
log " Prune stale snaps: $PRUNE_STALE_SNAPSHOTS"
log " Prune uninstalled: $PRUNE_UNINSTALLED_KERNELS (confirm: $CONFIRM_PRUNE_UNINSTALLED)"
log "========================================"

ok_count=0
ghost_count=0
protected_count=0
stale_snapshot_count=0
uninstalled_kernel_count=0
moved_or_deleted_count=0
skipped_count=0

ensure_backup_dir() {
  if [[ -z "$BACKUP_DIR" ]]; then
    local ts
    ts="$(ts_now)"

    # Prefer a backup path OUTSIDE the entries dir so we never touch it by accident.
    # Fall back to inside ENTRIES_DIR if /var/backups isn't writable for some reason.
    if mkdir -p -- "$BACKUP_ROOT" 2>/dev/null; then
      BACKUP_DIR="$BACKUP_ROOT/bls-entries-$ts"
    else
      BACKUP_DIR="$ENTRIES_DIR/.scrub-ghost-backup-$ts"
    fi
  fi

  mkdir -p -- "$BACKUP_DIR"

  # Point latest -> this backup dir (best effort)
  if [[ "$BACKUP_DIR" == "$BACKUP_ROOT"/* ]]; then
    ln -sfn -- "$BACKUP_DIR" "$BACKUP_ROOT/latest" 2>/dev/null || true
  fi
}

backup_entries_tree() {
  # Makes a full copy of the current BLS entry files before any modifications.
  # This is independent from the "move ghosts into backup" behavior.
  ensure_backup_dir

  local full_dir="$BACKUP_DIR/full"
  mkdir -p -- "$full_dir"

  # Copy only top-level .conf entries (we never recurse), preserving metadata where possible.
  # cp -a on vfat won't preserve everything but it's still a good safety net.
  if compgen -G "$ENTRIES_DIR/*.conf" >/dev/null; then
    cp -a -- "$ENTRIES_DIR"/*.conf "$full_dir/" 2>/dev/null || cp -p -- "$ENTRIES_DIR"/*.conf "$full_dir/"
  fi

  {
    echo "timestamp=$(date -Is)"
    echo "entries_dir=$ENTRIES_DIR"
    echo "boot_dir=$BOOT_DIR"
    echo "delete_mode=$DELETE_MODE"
    if [[ -n "$SNAPPER_BACKUP_ID" ]]; then
      echo "snapper_backup_id=$SNAPPER_BACKUP_ID"
    fi
  } >"$BACKUP_DIR/manifest.txt" || true
}

snapper_backup_snapshot() {
  # Best-effort snapper snapshot: may not include ESP contents, but provides system rollback.
  # We do not fail the script if snapper isn't configured.
  if command -v snapper >/dev/null 2>&1; then
    local desc
    desc="scrub-ghost: pre-clean $(date -Is)"
    SNAPPER_BACKUP_ID="$(snapper --no-dbus create --type single --cleanup-algorithm number --description "$desc" 2>/dev/null | tr -dc '0-9' || true)"
    if [[ -n "$SNAPPER_BACKUP_ID" ]]; then
      log "Snapper backup created: #$SNAPPER_BACKUP_ID"
    else
      warn "Snapper backup requested but could not create snapshot (snapper may be unconfigured)"
    fi
  else
    warn "Snapper backup requested but snapper not installed"
  fi
}

# If applying changes, create backups BEFORE touching entries.
if [[ "$DRY_RUN" == false ]]; then
  if [[ "$AUTO_SNAPPER_BACKUP" == true ]]; then
    snapper_backup_snapshot
  fi
  if [[ "$AUTO_BACKUP" == true ]]; then
    backup_entries_tree
    log "Entry backup saved to: $BACKUP_DIR"
  fi
fi

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

  # Snapshot verification/protection.
  snap_num="$(snapshot_num_from_entry "$entry")"
  snap_present=false
  if [[ "$VERIFY_SNAPSHOTS" == true && -n "$snap_num" ]]; then
    if snapshot_exists "$snap_num"; then
      snap_present=true
    else
      snap_present=false
    fi
  elif [[ -n "$snap_num" ]]; then
    # Without snapper verification, fall back to simple on-disk check.
    if [[ -d "/.snapshots/$snap_num/snapshot" ]]; then
      snap_present=true
    fi
  fi

  # Kernel modules verification (helps detect entries for kernels not installed anymore)
  kver=""
  modules_present=true
  if [[ "$VERIFY_KERNEL_MODULES" == true ]]; then
    kver="$(kernel_version_from_linux_path "$kernel_path" 2>/dev/null || true)"
    if [[ -n "$kver" ]]; then
      if ! modules_dir_exists_for_kver "$kver"; then
        modules_present=false
      fi
    fi
  fi

  # Kernel image missing -> ghost.
  if [[ ! -e "$kernel_full" ]]; then
    :
  else
    # Kernel image exists, but we may still want to flag stale snapper/uninstalled kernels.
    if [[ -n "$snap_num" && "$VERIFY_SNAPSHOTS" == true && "$snap_present" == false ]]; then
      stale_snapshot_count=$((stale_snapshot_count + 1))
      log "[STALE-SNAPSHOT] $(basename -- "$entry") (snapshot #$snap_num not present)"

      if [[ "$DRY_RUN" == true || "$PRUNE_STALE_SNAPSHOTS" == false ]]; then
        continue
      fi

      # Apply pruning (move/delete) for stale snapshot entries
      log "        action:  pruning stale snapshot entry"
      if [[ "$DELETE_MODE" == "delete" ]]; then
        rm -f -- "$entry"
      else
        ensure_backup_dir
        mv -- "$entry" "$BACKUP_DIR/"
      fi
      moved_or_deleted_count=$((moved_or_deleted_count + 1))
      continue
    fi

    if [[ "$modules_present" == false ]]; then
      uninstalled_kernel_count=$((uninstalled_kernel_count + 1))
      log "[UNINSTALLED-KERNEL] $(basename -- "$entry") (modules missing for ${kver:-unknown})"

      if [[ "$PRUNE_UNINSTALLED_KERNELS" == true && "$CONFIRM_PRUNE_UNINSTALLED" == false ]]; then
        log "        note:    pruning requires --confirm-uninstalled (extra safety flag)"
      fi

      if [[ "$DRY_RUN" == true || "$PRUNE_UNINSTALLED_KERNELS" == false || "$CONFIRM_PRUNE_UNINSTALLED" == false ]]; then
        continue
      fi

      log "        action:  pruning uninstalled-kernel entry"
      if [[ "$DELETE_MODE" == "delete" ]]; then
        rm -f -- "$entry"
      else
        ensure_backup_dir
        mv -- "$entry" "$BACKUP_DIR/"
      fi
      moved_or_deleted_count=$((moved_or_deleted_count + 1))
      continue
    fi

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
    if [[ -n "$snap_num" ]]; then
      log "        note:    references existing snapshot (#$snap_num)"
    else
      log "        note:    references existing snapshot"
    fi
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
log "   Stale snapshots:      $stale_snapshot_count"
log "   Uninstalled kernels:  $uninstalled_kernel_count"
log "   Skipped (malformed):  $skipped_count"
if [[ "$DRY_RUN" == false ]]; then
  log "   Changed:              $moved_or_deleted_count"
  if [[ -n "$SNAPPER_BACKUP_ID" ]]; then
    log "   Snapper backup:       #$SNAPPER_BACKUP_ID"
  fi
  if [[ -n "$BACKUP_DIR" ]]; then
    log "   Backup dir:           $BACKUP_DIR"
  fi
else
  log "   Changed:              0 (dry-run)"
  log ""
  log "To apply safely (move ghosts to backup):"
  log "  sudo bash $0 --force"
  log "To prune stale snapper entries too:"
  log "  sudo bash $0 --force --prune-stale-snapshots"
  log "To prune uninstalled-kernel entries too (extra safety confirm required):"
  log "  sudo bash $0 --force --prune-uninstalled --confirm-uninstalled"
  log "To permanently delete ghosts (and optionally pruned entries):"
  log "  sudo bash $0 --delete [--prune-stale-snapshots] [--prune-uninstalled --confirm-uninstalled]"
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
