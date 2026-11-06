# linux-hardering

Linux hardening toolkit for Debian/Ubuntu. Current version: **2.2**.

## Features

- Interactive RU/EN TUI and configuration-driven operation
- SSH hardening, firewall, Fail2ban, auditing and system security settings
- Multiple SSH public keys for the administrator (`PUBKEYS` separated by `|`)
- Dry-run support and configuration backups

## Run

```bash
sudo bash linux-harden.sh --help
sudo bash linux-harden.sh --dry-run
```

## Multiple SSH keys

Set `KEY_SOURCE='paste'` and specify one key in `PUBKEY` and additional keys in `PUBKEYS`, separated by `|`. The interactive setup also supports adding multiple keys. Existing authorized keys are preserved and duplicates skipped.

**Warning:** Test on a disposable VM with console access before changing SSH or firewall settings. Full integration testing has not been performed.
