# Scrub-GHOST
Grub/BLS cleanup tool for openSUSE Tumbleweed (sd-boot/BLS entries).

## Run
Dry-run scan:
- `sudo ./scrub.sh --dry-run`

Interactive menu:
- `sudo ./scrub.sh --menu`

## Install command (optional)
Installs the command to `/usr/local/bin/scrub-ghost`:
- `sudo ./install.sh`

## Systemd integration (optional, independent)
Systemd units are installed independently (not tied to `scrub.sh` location) using a wrapper that reads config from `/etc/default/scrub-ghost` or `/etc/sysconfig/scrub-ghost`:
- Install: `sudo ./systemd/install-systemd.sh`
- Enable timer: `sudo ./systemd/install-systemd.sh --enable-timer`

## Zypper integration (optional, independent)
- Install: `sudo ./zypp/install-zypp-hook.sh`
