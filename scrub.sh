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
ACTION="scan"  # scan | list-backups | restore | validate
RESTORE_FROM=""
RESTORE_PICK=""        # 1 = newest, 2 = second newest, etc.
RESTORE_ANYWAY=false
RESTORE_BEST=false

# Output
COLOR=true
VERBOSE=false

# Logging
DEBUG=false
LOG_FILE="/var/log/scrub-ghost.log"
LOG_FILE_SET=false

# Interactive menu
MENU_REQUESTED=false
NO_MENU=false

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
  --no-color             Disable colored output
  --verbose              Print extra details (including validation failures in --list-backups)
  --debug                Enable debug logging
  --log-file PATH         Write logs to PATH (default: /var/log/scrub-ghost.log)

Interactive:
  --menu                 Start interactive menu

Easy restore:
  --list-backups         List backup folders under backup root (numbered)
  --restore-latest       Restore BLS entries from the latest backup (validated)
  --restore-pick N       Restore from backup number N shown by --list-backups (validated)
  --restore-best         Restore from the newest backup that passes validation
  --restore-from DIR     Restore BLS entries from a specific backup directory (validated)
  --restore-anyway       Override failed validation (dangerous)

Validation only (no changes):
  --validate-latest      Validate latest backup without restoring
  --validate-pick N      Validate backup number N shown by --list-backups
  --validate-from DIR    Validate a specific backup without restoring

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
  sudo ./scrub.sh --validate-latest
  sudo ./scrub.sh --restore-pick 2
  sudo ./scrub.sh --restore-best
  sudo ./scrub.sh --restore-from /var/backups/scrub-ghost/bls-entries-YYYYMMDD-HHMMSS
USAGE
}

C_RESET=""
C_BOLD=""
C_RED=""
C_GREEN=""
C_YELLOW=""
C_BLUE=""
C_DIM=""

log_to_file() {
  # Best effort: write to LOG_FILE without ANSI codes.
  [[ -n "$LOG_FILE" ]] || return 0

  # Strip ANSI escapes before writing to file.
  local line
  line="$(printf '%b' "$*" | sed -r 's/\x1B\[[0-9;]*[mK]//g')"
  printf '%s %s\n' "$(date -Is)" "$line" >>"$LOG_FILE" 2>/dev/null || true
}

init_logging() {
  # Try requested file first; if not writable, fall back.
  if [[ -z "$LOG_FILE" ]]; then
    return 0
  fi

  local dir
  dir="$(dirname -- "$LOG_FILE")"
  mkdir -p -- "$dir" 2>/dev/null || true
  touch -- "$LOG_FILE" 2>/dev/null || true

  if [[ ! -w "$LOG_FILE" ]]; then
    # Fall back to BACKUP_ROOT (usually writable as root) then /tmp
    LOG_FILE="$BACKUP_ROOT/scrub-ghost.log"
    mkdir -p -- "$BACKUP_ROOT" 2>/dev/null || true
    touch -- "$LOG_FILE" 2>/dev/null || true

    if [[ ! -w "$LOG_FILE" ]]; then
      LOG_FILE="/tmp/scrub-ghost.log"
      touch -- "$LOG_FILE" 2>/dev/null || true
    fi
  fi
}

init_colors() {
  # Enable colors only when stdout is a TTY and the user hasn't disabled it.
  if [[ "$COLOR" != true ]]; then
    return 0
  fi
  if [[ ! -t 1 ]]; then
    return 0
  fi
  if [[ -n "${NO_COLOR:-}" ]]; then
    return 0
  fi

  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_DIM=$'\033[2m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
}

log() {
  printf '%b\n' "$*"
  log_to_file "$*"
}
warn() {
  printf '%bWARN:%b %s\n' "$C_YELLOW" "$C_RESET" "$*"
  log_to_file "WARN: $*"
}
err() {
  printf '%bERROR:%b %s\n' "$C_RED" "$C_RESET" "$*" >&2
  log_to_file "ERROR: $*"
}
debug() {
  if [[ "$DEBUG" == true ]]; then
    printf '%bDEBUG:%b %s\n' "$C_BLUE" "$C_RESET" "$*"
    log_to_file "DEBUG: $*"
  fi
}

ts_now() { date +%Y%m%d-%H%M%S; }

latest_backup_dir() {
  # Prefer explicit latest symlink; otherwise pick newest matching directory.
  if [[ -d "$BACKUP_ROOT/latest" ]]; then
    printf '%s\n' "$BACKUP_ROOT/latest"
    return 0
  fi

  ls -1dt "$BACKUP_ROOT"/bls-entries-* 2>/dev/null | head -n 1 || true
}

pick_nth_backup_dir() {
  local n="$1"
  [[ "$n" =~ ^[0-9]+$ ]] || return 1
  [[ "$n" -ge 1 ]] || return 1

  ls -1dt "$BACKUP_ROOT"/bls-entries-* 2>/dev/null | sed -n "${n}p" || true
}

list_backups() {
  mkdir -p -- "$BACKUP_ROOT" 2>/dev/null || true
  if ! ls -1d "$BACKUP_ROOT"/bls-entries-* >/dev/null 2>&1; then
    log "No backups found under: $BACKUP_ROOT"
    exit 0
  fi

  log "Backups under: $BACKUP_ROOT"
  log "(Use: --restore-pick N or --validate-pick N)"
  log "${C_DIM}GREEN = recommended (passes validation). RED = old/bad (fails validation).${C_RESET}"
  if [[ "$VERBOSE" == false ]]; then
    log "${C_DIM}(Tip: add --verbose to show why a backup is marked OLD.)${C_RESET}"
  fi

  local i=1
  while IFS= read -r d; do
    [[ -n "$d" ]] || continue

    local count
    count="$(ls -1 "$d"/full/*.conf 2>/dev/null | wc -l || true)"

    local sid=""
    local mid=""
    if [[ -f "$d/manifest.txt" ]]; then
      sid="$(awk -F= '$1=="snapper_backup_id" {print $2; exit}' "$d/manifest.txt" 2>/dev/null || true)"
      mid="$(awk -F= '$1=="machine_id" {print $2; exit}' "$d/manifest.txt" 2>/dev/null || true)"
    fi

    local extra=""
    [[ -n "$sid" ]] && extra+=" snapper=#$sid"
    [[ -n "$mid" ]] && extra+=" machine_id=${mid:0:8}…"

    local status_tag=""
    local status_color="$C_GREEN"
    if [[ "$VERBOSE" == true ]]; then
      if validate_backup_bootability "$d"; then
        status_tag="[OK]"
        status_color="$C_GREEN"
      else
        status_tag="[OLD]"
        status_color="$C_RED"
      fi
    else
      if validate_backup_bootability "$d" >/dev/null 2>&1; then
        status_tag="[OK]"
        status_color="$C_GREEN"
      else
        status_tag="[OLD]"
        status_color="$C_RED"
      fi
    fi

    if [[ -f "$d/manifest.txt" ]]; then
      log "${status_color}${status_tag}${C_RESET} $i) $d (full entries: $count)$extra"
    else
      log "${status_color}${status_tag}${C_RESET} $i) $d (full entries: $count; no manifest)"
    fi

    i=$((i + 1))
  done < <(ls -1dt "$BACKUP_ROOT"/bls-entries-* 2>/dev/null)
}

validate_backup_structure() {
  # Integrity check: backup looks like a backup (not necessarily bootable).
  local src="$1"
  [[ -d "$src" ]] || return 1
  [[ -d "$src/full" ]] || return 1
  compgen -G "$src/full/*.conf" >/dev/null || return 1

  local bad=0
  for f in "$src"/full/*.conf; do
    local kp
    kp="$(awk '$1 ~ /^linux(efi)?$/ {print $2; exit}' "$f" 2>/dev/null || true)"
    if [[ -z "$kp" ]]; then
      bad=$((bad + 1))
    fi
  done

  [[ "$bad" -eq 0 ]]
}

validate_backup_bootability() {
  # Strong validation: try to ensure the restored set won't obviously be broken.
  # Checks:
  # - each entry has linux path and it exists now
  # - initrd (if present) exists now
  # - snapper snapshots referenced still exist (if verification enabled)
  # - machine-id match if manifest provides it
  local src="$1"

  if ! validate_backup_structure "$src"; then
    err "validate: backup structure invalid: $src"
    return 1
  fi

  local this_mid=""
  if [[ -f /etc/machine-id ]]; then
    this_mid="$(tr -d '\n' </etc/machine-id 2>/dev/null || true)"
  fi

  local manifest_mid=""
  if [[ -f "$src/manifest.txt" ]]; then
    manifest_mid="$(awk -F= '$1=="machine_id" {print $2; exit}' "$src/manifest.txt" 2>/dev/null || true)"
  fi

  if [[ -n "$manifest_mid" && -n "$this_mid" && "$manifest_mid" != "$this_mid" ]]; then
    err "validate: machine-id mismatch (backup is from a different install)"
    err "validate: this=$this_mid backup=$manifest_mid"
    return 1
  fi

  local missing_kernel=0
  local missing_initrd=0
  local missing_snapshot=0

  for f in "$src"/full/*.conf; do
    local kp
    kp="$(awk '$1 ~ /^linux(efi)?$/ {print $2; exit}' "$f" 2>/dev/null || true)"
    local kfull
    kfull="$(resolve_boot_path "$kp" || true)"
    if [[ -z "$kfull" || ! -e "$kfull" ]]; then
      missing_kernel=$((missing_kernel + 1))
    fi

    local ip
    ip="$(awk '$1=="initrd" {print $2; exit}' "$f" 2>/dev/null || true)"
    if [[ -n "$ip" ]]; then
      local ifull
      ifull="$(resolve_boot_path "$ip" || true)"
      if [[ -z "$ifull" || ! -e "$ifull" ]]; then
        missing_initrd=$((missing_initrd + 1))
      fi
    fi

    if [[ "$VERIFY_SNAPSHOTS" == true ]]; then
      local sn
      sn="$(snapshot_num_from_entry "$f")"
      if [[ -n "$sn" ]]; then
        if ! snapshot_exists "$sn"; then
          missing_snapshot=$((missing_snapshot + 1))
        fi
      fi
    fi
  done

  if [[ "$missing_kernel" -ne 0 || "$missing_initrd" -ne 0 || "$missing_snapshot" -ne 0 ]]; then
    err "validate: failed: missing kernel=$missing_kernel initrd=$missing_initrd snapshots=$missing_snapshot"
    return 1
  fi

  return 0
}

pick_best_backup_dir() {
  # Choose newest backup that passes bootability validation.
  local d
  while IFS= read -r d; do
    [[ -n "$d" ]] || continue
    if validate_backup_bootability "$d"; then
      printf '%s\n' "$d"
      return 0
    fi
  done < <(ls -1dt "$BACKUP_ROOT"/bls-entries-* 2>/dev/null)

  return 1
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

  if ! validate_backup_structure "$src"; then
    err "restore: invalid backup structure: $src"
    exit 1
  fi

  if ! validate_backup_bootability "$src"; then
    if [[ "$RESTORE_ANYWAY" == false ]]; then
      err "restore blocked: backup failed validation"
      err "Use --restore-anyway to override"
      exit 1
    fi
    warn "Proceeding despite failed validation (--restore-anyway)"
  fi

  debug "Restoring entries from '$src' into '$ENTRIES_DIR'"

  # Backup current entries before replacing.
  local ts
  ts="$(ts_now)"
  local pre_dir="$BACKUP_ROOT/restore-pre-$ts"
  mkdir -p -- "$pre_dir"

  if compgen -G "$ENTRIES_DIR/*.conf" >/dev/null; then
    cp -a -- "$ENTRIES_DIR"/*.conf "$pre_dir/" 2>/dev/null || cp -p -- "$ENTRIES_DIR"/*.conf "$pre_dir/"
  fi

  # Safer restore strategy:
  # 1) Copy all files from backup over (overwrite/replace)
  # 2) Remove any extra .conf files not present in the backup set
  declare -A wanted
  local bf
  for bf in "$src"/full/*.conf; do
    local base
    base="$(basename -- "$bf")"
    wanted["$base"]=1
    cp -a -- "$bf" "$ENTRIES_DIR/$base" 2>/dev/null || cp -p -- "$bf" "$ENTRIES_DIR/$base"
  done

  local cur
  for cur in "$ENTRIES_DIR"/*.conf; do
    [[ -e "$cur" ]] || continue
    local base
    base="$(basename -- "$cur")"
    if [[ -z "${wanted[$base]+x}" ]]; then
      rm -f -- "$cur"
    fi
  done

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

ORIG_ARGC=$#

# Argument parsing
while [[ $# -gt 0 ]]; do
  case "$1" in
    --menu)
      MENU_REQUESTED=true
      ;;
    --no-menu)
      NO_MENU=true
      ;;
    --verbose)
      VERBOSE=true
      ;;
    --debug)
      DEBUG=true
      ;;
    --log-file)
      shift
      LOG_FILE="${1:-}"
      LOG_FILE_SET=true
      ;;
    --no-color)
      COLOR=false
      ;;
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
    --restore-pick)
      ACTION="restore"
      shift
      RESTORE_PICK="${1:-}"
      ;;
    --restore-best)
      ACTION="restore"
      RESTORE_BEST=true
      ;;
    --restore-from)
      ACTION="restore"
      shift
      RESTORE_FROM="${1:-}"
      ;;
    --restore-anyway)
      RESTORE_ANYWAY=true
      ;;

    --validate-latest)
      ACTION="validate"
      RESTORE_FROM="__LATEST__"
      ;;
    --validate-pick)
      ACTION="validate"
      shift
      RESTORE_PICK="${1:-}"
      ;;
    --validate-from)
      ACTION="validate"
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

if [[ "$BOOT_DIR_SET" == false ]]; then
  BOOT_DIR="$(dirname "$(dirname "$ENTRIES_DIR")")"
fi

if [[ ! -d "$BOOT_DIR" ]]; then
  warn "Boot root dir not found: $BOOT_DIR (path checks may be wrong)"
fi

# Initialize colors/logging once we parsed flags.
init_colors
init_logging
if [[ -n "$LOG_FILE" ]]; then
  debug "Logging to: $LOG_FILE"
fi

if [[ "$VERIFY_SNAPSHOTS" == true ]]; then
  load_snapper_snapshot_set
fi

prompt_enter_to_continue() {
  # shellcheck disable=SC2162
  read -r -p "Press Enter to continue..." _ </dev/tty 2>/dev/null || true
}

build_common_flags() {
  COMMON_FLAGS=()

  [[ "$COLOR" == false ]] && COMMON_FLAGS+=("--no-color")
  [[ "$VERBOSE" == true ]] && COMMON_FLAGS+=("--verbose")
  [[ "$DEBUG" == true ]] && COMMON_FLAGS+=("--debug")

  # Keep log file consistent across invocations
  if [[ -n "$LOG_FILE" ]]; then
    COMMON_FLAGS+=("--log-file" "$LOG_FILE")
  fi

  [[ "$AUTO_BACKUP" == false ]] && COMMON_FLAGS+=("--no-backup")
  [[ "$AUTO_SNAPPER_BACKUP" == false ]] && COMMON_FLAGS+=("--no-snapper-backup")

  [[ "$VERIFY_SNAPSHOTS" == false ]] && COMMON_FLAGS+=("--no-verify-snapshots")
  [[ "$VERIFY_KERNEL_MODULES" == false ]] && COMMON_FLAGS+=("--no-verify-modules")

  # Keep using same backup root if user changed it
  [[ -n "$BACKUP_ROOT" ]] && COMMON_FLAGS+=("--backup-root" "$BACKUP_ROOT")

  # Preserve manual directory overrides if used
  [[ "$ENTRIES_DIR_SET" == true ]] && COMMON_FLAGS+=("--entries-dir" "$ENTRIES_DIR")
  [[ "$BOOT_DIR_SET" == true ]] && COMMON_FLAGS+=("--boot-dir" "$BOOT_DIR")
}

run_sub() {
  build_common_flags
  SCRUB_GHOST_NO_MENU=1 bash "$0" --no-menu "${COMMON_FLAGS[@]}" "$@"
}

menu_header() {
  log ""
  log "${C_BOLD}scrub-ghost interactive menu${C_RESET}"
  log "Entries: $ENTRIES_DIR"
  log "Boot:    $BOOT_DIR"
  log "Backup:  $BACKUP_ROOT"
  log "Log:     ${LOG_FILE:-disabled}"
  log ""
}

menu_main() {
  while true; do
    menu_header
    log "1) Scan (dry-run)"
    log "2) Clean: prune stale Snapper entries (safe move + backups)"
    log "3) Clean: remove ghosts only (safe move + backups)"
    log "4) Clean: ghosts + stale Snapper entries (safe move + backups)"
    log "5) Clean: prune uninstalled-kernel entries (requires confirm flag)"
    log ""
    log "6) Backups: list"
    log "7) Backups: validate (submenu)"
    log "8) Backups: restore (submenu)"
    log ""
    log "9) Settings (submenu)"
    log "0) Exit"
    log ""

    local choice
    read -r -p "> " choice </dev/tty || return 0

    case "$choice" in
      1)
        run_sub --dry-run
        prompt_enter_to_continue
        ;;
      2)
        run_sub --force --prune-stale-snapshots
        prompt_enter_to_continue
        ;;
      3)
        run_sub --force
        prompt_enter_to_continue
        ;;
      4)
        run_sub --force --prune-stale-snapshots
        prompt_enter_to_continue
        ;;
      5)
        log "This will only prune uninstalled-kernel entries if you also pass --confirm-uninstalled."
        log "Type YES to proceed with prune-uninstalled+confirm:"
        local yn
        read -r -p "> " yn </dev/tty || true
        if [[ "$yn" == "YES" ]]; then
          run_sub --force --prune-uninstalled --confirm-uninstalled
        else
          log "Cancelled."
        fi
        prompt_enter_to_continue
        ;;
      6)
        run_sub --list-backups
        prompt_enter_to_continue
        ;;
      7)
        menu_validate
        ;;
      8)
        menu_restore
        ;;
      9)
        menu_settings
        ;;
      0)
        return 0
        ;;
      *)
        log "Invalid option."
        prompt_enter_to_continue
        ;;
    esac
  done
}

menu_validate() {
  while true; do
    menu_header
    log "Validate backups"
    log "1) Validate latest"
    log "2) Validate pick number"
    log "3) Back"

    local choice
    read -r -p "> " choice </dev/tty || return 0

    case "$choice" in
      1)
        run_sub --validate-latest
        prompt_enter_to_continue
        ;;
      2)
        local n
        read -r -p "Pick number: " n </dev/tty || true
        run_sub --validate-pick "$n"
        prompt_enter_to_continue
        ;;
      3)
        return 0
        ;;
      *)
        log "Invalid option."
        prompt_enter_to_continue
        ;;
    esac
  done
}

menu_restore() {
  while true; do
    menu_header
    log "Restore backups (validated)"
    log "1) Restore latest"
    log "2) Restore best (newest passing validation)"
    log "3) Restore pick number"
    log "4) Back"

    local choice
    read -r -p "> " choice </dev/tty || return 0

    case "$choice" in
      1)
        run_sub --restore-latest
        prompt_enter_to_continue
        ;;
      2)
        run_sub --restore-best
        prompt_enter_to_continue
        ;;
      3)
        run_sub --list-backups
        local n
        read -r -p "Pick number: " n </dev/tty || true
        run_sub --restore-pick "$n"
        prompt_enter_to_continue
        ;;
      4)
        return 0
        ;;
      *)
        log "Invalid option."
        prompt_enter_to_continue
        ;;
    esac
  done
}

menu_settings() {
  while true; do
    menu_header
    log "Settings (these affect menu-run commands by passing flags)"
    log "1) Toggle verbose (currently: $VERBOSE)"
    log "2) Toggle debug  (currently: $DEBUG)"
    log "3) Toggle color  (currently: $COLOR)"
    log "4) Toggle verify snapshots (currently: $VERIFY_SNAPSHOTS)"
    log "5) Toggle verify modules   (currently: $VERIFY_KERNEL_MODULES)"
    log "6) Toggle auto backup      (currently: $AUTO_BACKUP)"
    log "7) Toggle auto snapper     (currently: $AUTO_SNAPPER_BACKUP)"
    log "8) Back"

    local choice
    read -r -p "> " choice </dev/tty || return 0

    case "$choice" in
      1) VERBOSE=$([[ "$VERBOSE" == true ]] && echo false || echo true) ;;
      2) DEBUG=$([[ "$DEBUG" == true ]] && echo false || echo true) ;;
      3) COLOR=$([[ "$COLOR" == true ]] && echo false || echo true); init_colors ;;
      4) VERIFY_SNAPSHOTS=$([[ "$VERIFY_SNAPSHOTS" == true ]] && echo false || echo true) ;;
      5) VERIFY_KERNEL_MODULES=$([[ "$VERIFY_KERNEL_MODULES" == true ]] && echo false || echo true) ;;
      6) AUTO_BACKUP=$([[ "$AUTO_BACKUP" == true ]] && echo false || echo true) ;;
      7) AUTO_SNAPPER_BACKUP=$([[ "$AUTO_SNAPPER_BACKUP" == true ]] && echo false || echo true) ;;
      8) return 0 ;;
      *) log "Invalid option." ;;
    esac

    prompt_enter_to_continue
  done
}

# Interactive menu: if requested OR no args and running on a TTY.
# Uses ORIG_ARGC because we've shifted args during parsing.
if [[ "$NO_MENU" == false && -z "${SCRUB_GHOST_NO_MENU:-}" ]]; then
  if [[ "$MENU_REQUESTED" == true || ( "$ORIG_ARGC" -eq 0 && -t 0 && -t 1 ) ]]; then
    menu_main
    exit 0
  fi
fi

# Handle non-scan actions after BOOT_DIR and snapper set are ready.
if [[ "$ACTION" == "list-backups" ]]; then
  list_backups
  exit 0
fi

if [[ "$ACTION" == "validate" ]]; then
  mkdir -p -- "$BACKUP_ROOT" 2>/dev/null || true

  if [[ -n "$RESTORE_PICK" ]]; then
    RESTORE_FROM="$(pick_nth_backup_dir "$RESTORE_PICK" || true)"
  elif [[ "$RESTORE_FROM" == "__LATEST__" ]]; then
    RESTORE_FROM="$(latest_backup_dir)"
  fi

  if [[ -z "$RESTORE_FROM" ]]; then
    err "validate: no backup found (use --list-backups)"
    exit 1
  fi

  if validate_backup_bootability "$RESTORE_FROM"; then
    log "Backup validation OK: $RESTORE_FROM"
    exit 0
  else
    err "Backup validation FAILED: $RESTORE_FROM"
    exit 1
  fi
fi

if [[ "$ACTION" == "restore" ]]; then
  mkdir -p -- "$BACKUP_ROOT" 2>/dev/null || true

  if [[ -n "$RESTORE_PICK" ]]; then
    RESTORE_FROM="$(pick_nth_backup_dir "$RESTORE_PICK" || true)"
  elif [[ "$RESTORE_BEST" == true ]]; then
    RESTORE_FROM="$(pick_best_backup_dir || true)"
  elif [[ "$RESTORE_FROM" == "__LATEST__" ]]; then
    RESTORE_FROM="$(latest_backup_dir)"
  fi

  if [[ -z "$RESTORE_FROM" ]]; then
    err "restore: no suitable backup found (use --list-backups)"
    exit 1
  fi

  restore_entries_from_backup "$RESTORE_FROM"
  exit 0
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
    if [[ -f /etc/machine-id ]]; then
      echo "machine_id=$(tr -d '\n' </etc/machine-id 2>/dev/null || true)"
    fi
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
    if validate_backup_structure "$BACKUP_DIR"; then
      log "Entry backup saved to: $BACKUP_DIR"
    else
      err "Backup integrity check failed; refusing to proceed with cleanup"
      err "(pass --no-backup if you really want to run without backups)"
      exit 1
    fi
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
      log "${C_RED}[STALE-SNAPSHOT]${C_RESET} $(basename -- "$entry") ${C_DIM}(snapshot #$snap_num not present)${C_RESET}"

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
      log "${C_YELLOW}[UNINSTALLED-KERNEL]${C_RESET} $(basename -- "$entry") ${C_DIM}(modules missing for ${kver:-unknown})${C_RESET}"

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

    log "${C_GREEN}[OK]${C_RESET}   $(basename -- "$entry")"
    ok_count=$((ok_count + 1))
    continue
  fi

  # Kernel missing -> likely a ghost entry.
  ghost_count=$((ghost_count + 1))

  log ""
  log "${C_RED}[GHOST]${C_RESET} $(basename -- "$entry")"
  log "        linux:   $kernel_path"
  log "        lookup:  $kernel_full"

  if [[ "$snap_present" == true ]]; then
    if [[ -n "$snap_num" ]]; then
      log "        note:    references existing snapshot (#$snap_num)"
    else
      log "        note:    references existing snapshot"
    fi
    log "        action:  ${C_BLUE}SKIP${C_RESET} (protected snapshot entry)"
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
