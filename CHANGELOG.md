# Changelog

## 1.0.1

- Fixed SSH public-key authentication with explicitly selected identity files.
- Added support for SSH agent keys and interactive unlocking of passphrase-protected identity files.
- Added the conventional `--identity-file` option while keeping the legacy `--identity_file` spelling compatible.
- Changed the no-configuration default language to English, independent of the system locale.
- Added an end-to-end SSH key authentication test and revalidated the existing test suite.

## 1.0.0

- Initial `ssh-tun` release.
- Static Linux binaries for amd64 and arm64.
- HTTP, HTTPS CONNECT, SOCKS5, and IPv4 TUN forwarding over SSH.
- SSH jump hosts and strict host-key verification.
- YAML configuration and English/Russian CLI localization.
- Routing rules with PROXY, DIRECT, and REJECT actions.
- systemd and OpenRC service installation.
