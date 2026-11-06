# linux-hardering

Bash toolkit for initial Debian/Ubuntu server hardening (RU/EN).

## Files

- [`linux-harden.sh`](./linux-harden.sh) — original v2.0 script.
- [`development`](../../tree/development) — development branch (v2.2 script upload still pending).

## Usage

```bash
sudo bash linux-harden.sh --help
sudo bash linux-harden.sh --dry-run
```

**Security warning:** Test on a disposable VM with console access before changing SSH, firewall or Docker networking. The original script is not production-validated. Version 2.2, including multiple SSH public keys, is not yet published in this repository.
