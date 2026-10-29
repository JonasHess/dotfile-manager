#!/bin/sh
# Generic bootstrap for dfm (dotfile-manager). Downloads the latest release
# for this machine, verifies the checksum and runs it. The vault comes from
# the DFM_VAULT environment variable or the first argument:
#   curl -fsSL https://raw.githubusercontent.com/JonasHess/dotfile-manager/main/install.sh | DFM_VAULT=https://github.com/you/your-vault.git sh
# A personal vault created with "dfm vault init" ships its own install.sh
# with the vault URL baked in, which is the one-liner most people want.
set -eu
TOOL_REPO="${DFM_TOOL_REPO:-JonasHess/dotfile-manager}"
VAULT_URL="${DFM_VAULT:-${1:-}}"
BIN_DIR="${DFM_BIN_DIR:-$HOME/.local/bin}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  armv7l|armv6l) arch=arm ;;
  *) echo "unsupported CPU: $arch" >&2; exit 1 ;;
esac
case "$os" in darwin|linux) ;; *) echo "unsupported OS: $os" >&2; exit 1 ;; esac

fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -q "$1" -O "$2"
  else echo "need curl or wget" >&2; exit 1; fi
}

base="https://github.com/$TOOL_REPO/releases/latest/download"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fetch "$base/dfm-$os-$arch" "$tmp/dfm"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS"
expected=$(grep " dfm-$os-$arch\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)
if command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum "$tmp/dfm" | cut -d' ' -f1)
else actual=$(shasum -a 256 "$tmp/dfm" | cut -d' ' -f1); fi
[ -n "$expected" ] && [ "$expected" = "$actual" ] || { echo "checksum mismatch for dfm-$os-$arch" >&2; exit 1; }

mkdir -p "$BIN_DIR"
install -m 0755 "$tmp/dfm" "$BIN_DIR/dfm"
echo "dfm installed to $BIN_DIR/dfm"
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) echo "note: add $BIN_DIR to your PATH" ;; esac
if [ -n "$VAULT_URL" ]; then
  exec "$BIN_DIR/dfm" --vault "$VAULT_URL" </dev/tty
fi
echo "run: dfm --vault <your vault URL>   or   dfm vault init <dir> to create one"
