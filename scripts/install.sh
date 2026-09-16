#!/usr/bin/env sh
# ssh-tun installer for Linux.

set -eu

REPOSITORY="zukhovich/ssh-tun"
VERSION="${SSH_TUN_VERSION:-}"
INSTALL_DIR="${SSH_TUN_INSTALL_DIR:-${HOME}/.local/bin}"
BINARY="ssh-tun"
INSTALL_COMPLETIONS=1

info() { printf '[INFO] %s\n' "$*"; }
fail() {
    printf '[ERROR] %s\n' "$*" >&2
    exit 1
}
need() { command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"; }

while [ $# -gt 0 ]; do
    case "$1" in
    --version)
        [ $# -ge 2 ] || fail "--version requires a value"
        VERSION="$2"
        shift 2
        ;;
    --install-dir)
        [ $# -ge 2 ] || fail "--install-dir requires a value"
        INSTALL_DIR="$2"
        shift 2
        ;;
    --no-completions)
        INSTALL_COMPLETIONS=0
        shift
        ;;
    -h | --help)
        printf '%s\n' 'Usage: install.sh [--version VERSION] [--install-dir DIR] [--no-completions]'
        exit 0
        ;;
    *) fail "Unknown option: $1" ;;
    esac
done

[ "$(uname -s)" = "Linux" ] || fail "ssh-tun supports Linux only"
case "$(uname -m)" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*) fail "Unsupported architecture: $(uname -m)" ;;
esac

need tar
need sha256sum
if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL "$1" -o "$2"; }
    fetch_stdout() { curl -fsSL "$1"; }
    latest_release_url() { curl -fsSLI -o /dev/null -w '%{url_effective}' "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -q "$1" -O "$2"; }
    fetch_stdout() { wget -qO- "$1"; }
    latest_release_url() { wget -q -S --spider "$1" 2>&1 | sed -n 's/^[[:space:]]*Location: \([^[:space:]]*\).*/\1/p' | tail -n 1; }
else
    fail "curl or wget is required"
fi

if [ -z "$VERSION" ]; then
    RELEASE_JSON=$(fetch_stdout "https://api.github.com/repos/${REPOSITORY}/releases/latest" 2>/dev/null || true)
    TAG=$(printf '%s\n' "$RELEASE_JSON" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
    if [ -z "$TAG" ]; then
        LATEST_URL=$(latest_release_url "https://github.com/${REPOSITORY}/releases/latest" 2>/dev/null || true)
        TAG=${LATEST_URL##*/}
    fi
    [ -n "$TAG" ] || fail "Could not determine the latest release version"
    VERSION=${TAG#v}
else
    VERSION=${VERSION#v}
fi

ASSET="ssh-tun_${VERSION}_linux_${ARCH}.tar.gz"
BASE_URL="https://github.com/${REPOSITORY}/releases/download/v${VERSION}"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

info "Downloading ${ASSET}"
fetch "${BASE_URL}/${ASSET}" "${TMP_DIR}/${ASSET}" || fail "Download failed"
fetch "${BASE_URL}/SHA256SUMS" "${TMP_DIR}/SHA256SUMS" || fail "SHA256SUMS download failed"
CHECKSUM_LINE=$(grep "  ${ASSET}$" "${TMP_DIR}/SHA256SUMS" || true)
[ -n "$CHECKSUM_LINE" ] || fail "Checksum for ${ASSET} not found"
printf '%s\n' "$CHECKSUM_LINE" >"${TMP_DIR}/SHA256SUMS.asset"
(cd "$TMP_DIR" && sha256sum -c SHA256SUMS.asset) || fail "Checksum verification failed"
tar -xzf "${TMP_DIR}/${ASSET}" -C "$TMP_DIR"
[ -f "${TMP_DIR}/ssh-tun_${VERSION}_linux_${ARCH}" ] || fail "Binary not found in archive"

mkdir -p "$INSTALL_DIR"
if [ -w "$INSTALL_DIR" ]; then
    install -m 0755 "${TMP_DIR}/ssh-tun_${VERSION}_linux_${ARCH}" "${INSTALL_DIR}/${BINARY}"
else
    need sudo
    sudo install -m 0755 "${TMP_DIR}/ssh-tun_${VERSION}_linux_${ARCH}" "${INSTALL_DIR}/${BINARY}"
fi

if [ "$INSTALL_COMPLETIONS" -eq 1 ]; then
    if command -v bash >/dev/null 2>&1; then
        mkdir -p "${HOME}/.local/share/bash-completion/completions"
        "${INSTALL_DIR}/${BINARY}" completion bash >"${HOME}/.local/share/bash-completion/completions/ssh-tun"
    fi
    if command -v zsh >/dev/null 2>&1; then
        mkdir -p "${ZDOTDIR:-$HOME}/.zsh/completions"
        "${INSTALL_DIR}/${BINARY}" completion zsh >"${ZDOTDIR:-$HOME}/.zsh/completions/_ssh-tun"
    fi
    if command -v fish >/dev/null 2>&1; then
        mkdir -p "${HOME}/.config/fish/completions"
        "${INSTALL_DIR}/${BINARY}" completion fish >"${HOME}/.config/fish/completions/ssh-tun.fish"
    fi
fi

info "ssh-tun ${VERSION} installed as ${INSTALL_DIR}/${BINARY}"
