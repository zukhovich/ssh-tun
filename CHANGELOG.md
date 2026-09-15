# Changelog

## 1.0.3

- Added cross-compilation support and release packaging scripts for Windows (amd64 and arm64) alongside Linux binaries.
- Updated documentation and installation scripts to reference version 1.0.3.
- Improved Makefile targets and automated binary testing workflow.

## 1.0.2

- Added first-connection host-key confirmation and automatic persistence to `known_hosts`, matching the familiar OpenSSH workflow while still rejecting changed or revoked keys.
- Offered SSH keys, configured passwords, and keyboard-interactive authentication in a single handshake, avoiding duplicate connections and misleading authentication errors.
- Made GNOME system-proxy integration opt-in instead of a startup requirement.
- Changed missing or unusable `gsettings` handling to a warning so HTTP, SOCKS5, and SSH services keep running without desktop integration.
- Kept the Linux release binaries statically linked; no new runtime dependency is required for the default proxy workflow.
- Added regression coverage for first-use host keys, changed host keys, default system-proxy behavior, and missing `gsettings`.

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
