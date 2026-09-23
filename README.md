# ssh-tun

[Русская документация](README.ru.md)

**Version 1.0.4**

`ssh-tun` is a self-contained command-line network proxy for Linux and Windows. It carries HTTP, HTTPS CONNECT, SOCKS5, and TUN traffic through SSH and supports jump hosts, routing rules, subnet mapping, automatic reconnection, native service installation, and OS-aware configuration templates.

Repository: <https://github.com/zukhovich/ssh-tun>

## Features

- HTTP and HTTPS CONNECT proxy over SSH.
- SOCKS5 CONNECT proxy with IPv4, IPv6, and domain-name requests.
- IPv4 TUN mode with TCP and DNS forwarding.
- Direct, proxied, and rejected routes selected by YAML rules.
- SSH jump-host chains.
- OpenSSH-style first-use host-key confirmation with strict mismatch detection.
- English and Russian command-line interface.
- Strict YAML application configuration.
- Optional GNOME system proxy setup with state restoration.
- Native systemd, OpenRC, and Windows Service installation.
- OS-aware configuration template generation.
- Automatic SSH channel monitoring and reconnection.
- Static Linux and standalone Windows binaries for `amd64` and `arm64`.

## Installation

Install version 1.0.4 from GitHub Releases:

```sh
curl -fsSL https://raw.githubusercontent.com/zukhovich/ssh-tun/main/scripts/install.sh | sh
```

Install into a custom directory:

```sh
curl -fsSL https://raw.githubusercontent.com/zukhovich/ssh-tun/main/scripts/install.sh |
  sh -s -- --version 1.0.4 --install-dir "$HOME/bin"
```

## Build From Source

Go 1.25.5 or newer is required.

```sh
git clone https://github.com/zukhovich/ssh-tun.git
cd ssh-tun
make test vet build
file build/ssh-tun
```

The main output is `build/ssh-tun`, a stripped, statically linked Linux executable. Release packaging also produces standalone Linux and Windows binaries for `amd64` and `arm64`.

Create release archives and checksums:

```sh
make package-release
```

## Quick Start

Connect directly; on first use, verify the displayed host-key fingerprint and answer `yes`. The accepted key is saved to `~/.ssh/known_hosts` automatically:

```sh
ssh-tun user@example.com --http 127.0.0.1:8080 --socks5 127.0.0.1:1080
```

Use a specific private key with `-i`/`--identity-file`:

```sh
ssh-tun user@example.com --identity-file ~/.ssh/id_ed25519
```

When no identity file is specified, `ssh-tun` uses keys from `ssh-agent` and then tries standard unencrypted files in `~/.ssh`. Passphrase-protected identity files can be unlocked interactively, or loaded into `ssh-agent` for non-interactive use. Available key, password, and keyboard-interactive methods are offered in one SSH handshake.

Desktop proxy configuration is disabled by default and is not required. Use `--sys-proxy` to enable GNOME integration. If `gsettings` is unavailable, ssh-tun logs a warning and keeps the local proxies running.

Use the proxies:

```sh
curl -x http://127.0.0.1:8080 https://example.org
curl --proxy socks5h://127.0.0.1:1080 https://example.org
```

## Configuration

Generate a template tailored to the current operating system (`~/.ssh` paths on Linux, `%USERPROFILE%`/`%PROGRAMDATA%` paths on Windows):

```sh
ssh-tun --write-config ./ssh-tun.yaml
```

Ready-to-copy Linux examples are also provided in [`configs/linux/config.yaml`](configs/linux/config.yaml) and [`configs/linux/rules.yaml`](configs/linux/rules.yaml).

Run with it:

```sh
ssh-tun --config ./ssh-tun.yaml
```

Precedence is: built-in defaults, YAML, explicitly supplied CLI options. Unknown YAML fields are rejected. Avoid storing passwords in YAML; use keys or a protected secret mechanism.

## Routing Rules

```yaml
mode: rule
rules:
  - DOMAIN-SUFFIX,example.org,DIRECT
  - DOMAIN,blocked.example.org,REJECT
  - IP-CIDR,10.0.0.0/8,PROXY
  - MATCH,,PROXY
```

Modes: `rule`, `direct`, `global`. Actions: `PROXY`, `DIRECT`, `REJECT`. The first matching rule wins.

## TUN Mode

```sh
sudo ssh-tun user@example.com --tun-route 10.20.0.0/16
sudo ssh-tun user@example.com --tun-global
```

Linux TUN mode requires root privileges and `iproute2`; Windows TUN mode requires an elevated Administrator console. Version 1.0.4 forwards IPv4 TCP and DNS traffic; general UDP forwarding is not implemented.

## Language

ssh-tun uses standard gettext locale selection. It checks `LANGUAGE`, `LC_ALL`, `LC_MESSAGES`, and `LANG` in that order. For example:

```sh
LANGUAGE=ru ssh-tun --help
LANGUAGE=en ssh-tun --help
```

With a Russian system locale such as `LANG=ru_RU.UTF-8`, no override is needed. A legacy `language` field in version 1 YAML files is accepted for compatibility but ignored.

## Automatic Reconnection

Enable SSH channel monitoring and automatic reconnection without restarting the local HTTP/SOCKS listeners:

```sh
ssh-tun user@example.com --auto-reconnect \
  --keepalive-interval 15s --reconnect-interval 5s
```

The same settings are available as `ssh.auto_reconnect`, `ssh.keepalive_interval`, and `ssh.reconnect_interval` in YAML.

## systemd, OpenRC, and Windows services

Create a permanent configuration first:

```sh
sudo mkdir -p /etc/ssh-tun
sudo ssh-tun --write-config /etc/ssh-tun/config.yaml
sudo chmod 600 /etc/ssh-tun/config.yaml
```

Install or remove a native service selected automatically for the current OS:

```sh
ssh-tun --config /path/to/config.yaml --install-service auto
ssh-tun --config /path/to/config.yaml --remove-service auto
```

On Linux, `auto` selects systemd or OpenRC. On Windows it creates/removes a Windows Service through `sc.exe`; run the console as Administrator. Linux service operations require root. A service must use non-interactive SSH authentication. GNOME `--sys-proxy` is intended for an interactive desktop session and normally should be disabled in a service.

## Security

- Never commit private keys, passwords, tokens, generated `known_hosts`, or real production configuration files.
- Host-key verification is enabled by default. Unknown keys require interactive confirmation; changed and revoked keys are rejected.
- `--insecure-host-key` disables verification and is unsafe.
- `--pass` exposes a password through process arguments; SSH keys are recommended.
- Bind proxy listeners to loopback unless remote clients are intentionally allowed.
- Graceful shutdown restores routes and desktop proxy settings. `SIGKILL` prevents cleanup.

## License

`ssh-tun` is distributed under the [MIT License](LICENSE).
