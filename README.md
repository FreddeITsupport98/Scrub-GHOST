# Scrub-GHOST
`scrub-ghost` is a safety-focused maintenance tool for Boot Loader Specification (BLS) entry cleanup on openSUSE (commonly `sd-boot` with entries under `/boot/efi/loader/entries`).

It is designed to remove or quarantine *obviously stale* boot menu entries ("ghost" entries, stale snapper snapshots, etc.) while avoiding the common failure mode of deleting something you still need.

This repository provides:
- `scrub.sh`: the tool itself (interactive menu + CLI)
- `install.sh`: installer for the **command** (and optional integration management)
- Optional, independent integrations:
  - systemd unit/timer (weekly run)
  - zypp commit hook (run after zypper transactions)

## Disclaimer / high-stakes warning
Bootloaders are high-stakes. If you remove the wrong files you can end up with a system that won’t boot.

This tool defaults to **dry-run** and uses **backups**. Still:
- Always run `--dry-run` first.
- Keep at least one known-good boot entry.
- Know how to restore (see "Recovery" below).

## Quick start
Dry-run scan (recommended first):
- `sudo ./scrub.sh --dry-run`

Interactive menu:
- `sudo ./scrub.sh --menu`

Safe cleanup (moves entries to a backup directory; does not hard-delete):
- `sudo ./scrub.sh --force --prune-stale-snapshots`

List backups:
- `sudo ./scrub.sh --list-backups`

Validate latest backup:
- `sudo ./scrub.sh --validate-latest`

Restore (validated):
- `sudo ./scrub.sh --restore-best`

## What is a “ghost” entry?
A BLS entry is treated as a *ghost* when it references a kernel path (the `linux` / `linuxefi` line) that does not exist on disk.

## What is a “stale snapper” entry?
A BLS entry is treated as *stale snapshot* when it references `/.snapshots/<N>/snapshot` but snapshot `<N>` no longer exists.

The tool verifies snapshot existence via:
- `/.snapshots/<N>/snapshot` directory, and/or
- `snapper --no-dbus list` (if snapper is available)

## Safety guardrails
The tool contains multiple guardrails to avoid creating an unbootable state:

- Dry-run by default.
- Before modifying entries (`--force` / `--delete`), it creates:
  - a filesystem backup of the whole current entries set
  - an optional snapper snapshot (best-effort)
- Running kernel & latest installed kernel protection:
  - the entry matching `uname -r` (running kernel) is protected
  - the entry matching the newest version seen under `/lib/modules` / `/usr/lib/modules` is also protected
- Restore validation:
  - restore is blocked unless the backup passes validation (unless you pass `--restore-anyway`)

## Output / colors
When output is a terminal (TTY):
- Green: OK
- Red: GHOST / STALE-SNAPSHOT / OLD backups
- Yellow: UNINSTALLED-KERNEL warnings
- Blue: PROTECTED / SKIP actions

Disable colors:
- `--no-color`

## Logging
The tool logs to the console and also writes a log file.

Default log file:
- `/var/log/scrub-ghost.log`

Enable debug logging:
- `--debug`

Override the log file path:
- `--log-file /path/to/file.log`

## Interactive menu
Start the menu:
- `sudo ./scrub.sh --menu`

The menu is organized as:
- Scan
- Clean (safe move + backups)
- Backups/Restore
- Settings
- Paths/advanced
- Danger zone (permanent deletes)
- Install/uninstall

The menu is intended for humans.
For automation, prefer the CLI.

## CLI reference (most used)
Scan:
- `sudo ./scrub.sh --dry-run`

Generate shell completion (no root required):
- `./scrub.sh --completion zsh`
- `./scrub.sh --completion bash`

Clean safely (move to backup):
- `sudo ./scrub.sh --force`

Also prune stale snapper snapshot entries:
- `sudo ./scrub.sh --force --prune-stale-snapshots`

Prune entries for kernels not installed anymore (requires confirmation):
- `sudo ./scrub.sh --force --prune-uninstalled --confirm-uninstalled`

Hard delete (dangerous):
- `sudo ./scrub.sh --delete [--prune-stale-snapshots] [--prune-uninstalled --confirm-uninstalled]`

Optional: rebuild/update bootloader metadata after changes:
- `--rebuild-grub` (runs `grub2-mkconfig`)
- `--update-sdboot` (runs `sdbootutil update-kernels`)

Backups:
- `sudo ./scrub.sh --list-backups`
- `sudo ./scrub.sh --validate-latest`
- `sudo ./scrub.sh --validate-pick 2`

Restore (validated):
- `sudo ./scrub.sh --restore-latest`
- `sudo ./scrub.sh --restore-best`
- `sudo ./scrub.sh --restore-pick 2`
- `sudo ./scrub.sh --restore-from /var/backups/scrub-ghost/bls-entries-YYYYMMDD-HHMMSS`

Restore options:
- Additive restore is the default (does not delete newer entries).
- `--clean-restore` will remove extra current entries not present in the backup.
- `--restore-anyway` bypasses failed restore validation.

Backup rotation:
- `--keep-backups N` (default: 5; `0` disables rotation)

## Backups: where they go
Backups are created under:
- `/var/backups/scrub-ghost/bls-entries-YYYYMMDD-HHMMSS/`

Inside each backup:
- `full/` contains all `.conf` files copied from the entries directory
- `manifest.txt` includes basic metadata (timestamps, machine-id, etc.)

The tool also maintains:
- `/var/backups/scrub-ghost/latest` symlink (best-effort)

## Recovery (“oh no” plan)
If your boot menu is missing entries:

1) Boot any working entry (or a rescue environment).
2) Restore from the newest valid backup:
- `sudo scrub-ghost --restore-best --rebuild-grub`

If no backup validates but you still want to restore anyway (dangerous):
- `sudo scrub-ghost --restore-latest --restore-anyway --rebuild-grub`

## Install the command (optional)
Install/upgrade the command to `/usr/local/bin/scrub-ghost`:
- `sudo ./install.sh`

Uninstall everything (command + integration bits):
- `sudo ./install.sh --uninstall`

Install will also refresh existing integrations by default (if they are already present). You can disable refresh:
- `sudo ./install.sh --no-update-systemd --no-update-zypp`

Remove integrations without removing the command:
- `sudo ./install.sh --remove-systemd`
- `sudo ./install.sh --remove-zypp`

## Systemd integration (optional, independent)
Systemd is installed independently and is not tied to where `scrub.sh` lives.

Standalone note: if you downloaded only `scrub.sh` (without the full repo), the interactive menu can still install/remove systemd integration using built-in templates.

Install systemd unit/timer + wrapper:
- `sudo ./systemd/install-systemd.sh`

Enable the weekly timer:
- `sudo ./systemd/install-systemd.sh --enable-timer`

Remove systemd integration:
- `sudo ./systemd/install-systemd.sh --uninstall`

Configuration:
- `/etc/default/scrub-ghost` or `/etc/sysconfig/scrub-ghost`

The systemd unit executes a wrapper at:
- `/usr/local/libexec/scrub-ghost/run-systemd`

That wrapper reads:
- `SCRUB_GHOST_BIN` (path to scrub-ghost)
- `SCRUB_GHOST_ARGS=(...)` (bash array of args)

## Zypper (zypp) integration (optional, independent)
Standalone note: if you downloaded only `scrub.sh` (without the full repo), the interactive menu can still install/remove the hook using built-in templates.

Install hook:
- `sudo ./zypp/install-zypp-hook.sh`

Remove hook:
- `sudo ./zypp/install-zypp-hook.sh --uninstall`

## Notes
- Ghost/broken entry detection checks not only the `linux` path but also `initrd` (if present) and `devicetree` (if present). If any referenced file is missing, the entry is flagged as a ghost/broken entry.
- On read-only systems (MicroOS/Aeon), when applying changes the tool will try a temporary remount `rw` for the mountpoints containing the entries directory and backup root, then restore `ro` on exit. Disable this behavior with `--no-remount-rw`.
- `git` is not required to run the tool.
- You should treat `--delete`, `--clean-restore`, and `--restore-anyway` as danger flags.
