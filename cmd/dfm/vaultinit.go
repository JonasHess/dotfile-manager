package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// cmdVault handles "dfm vault init DIR": it lays out a new vault repository
// with the config file, the bootstrap script, the pre-commit guard and CI.
func cmdVault(args []string) error {
	if len(args) == 0 || args[0] != "init" {
		return errors.New("usage: dfm vault init DIR [--owner USER] [--dotfiles-repo URL] [--vault-url URL]")
	}
	fs := flag.NewFlagSet("vault init", flag.ContinueOnError)
	owner := fs.String("owner", "", "GitHub account that owns the keys")
	dotRepo := fs.String("dotfiles-repo", "", "ssh clone URL of the dotfiles repo")
	dotInstall := fs.String("dotfiles-install", "", "command to run inside the dotfiles checkout")
	vaultURL := fs.String("vault-url", "", "public clone URL of this vault, used by install.sh")
	toolRepo := fs.String("tool-repo", "JonasHess/dotfile-manager", "GitHub repo that publishes dfm releases")
	// Accept the directory before or after the flags.
	rest := args[1:]
	dir := ""
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		dir, rest = rest[0], rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return nil
	}
	if dir == "" && fs.NArg() == 1 {
		dir = fs.Arg(0)
	}
	if dir == "" || fs.NArg() > 1 {
		return errors.New("vault init needs exactly one DIR")
	}
	if _, err := os.Stat(filepath.Join(dir, "vault.toml")); err == nil {
		return fmt.Errorf("%s already contains a vault.toml", dir)
	}
	write := func(rel, content string, mode os.FileMode) error {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		return os.WriteFile(p, []byte(content), mode)
	}
	if *vaultURL == "" && *owner != "" {
		*vaultURL = "https://github.com/" + *owner + "/" + filepath.Base(dir) + ".git"
	}
	cfg := fmt.Sprintf(`# dfm vault configuration. Nothing in this file is secret.

[vault]
owner = %q

[dotfiles]
repo = %q
target = "~/repos/dotfiles"
install = %q

[legacy]
# What "Clean up old keys" looks for on machines set up before dfm.
authorized_keys_comments = []
private_keys = []
`, *owner, *dotRepo, *dotInstall)

	install := strings.ReplaceAll(strings.ReplaceAll(installTemplate, "__TOOL_REPO__", *toolRepo), "__VAULT_URL__", *vaultURL)
	err := errors.Join(
		write("vault.toml", cfg, 0o644),
		write("install.sh", install, 0o755),
		write("personas/.gitkeep", "", 0o644),
		write(".gitignore", "notes-local/\nid_ed25519*\nid_rsa*\n*.plain\n", 0o644),
		write(".githooks/pre-commit", preCommitHook, 0o755),
		write(".github/workflows/guard.yml", strings.ReplaceAll(guardWorkflow, "__TOOL_REPO__", *toolRepo), 0o644),
		write("README.md", fmt.Sprintf(readmeTemplate, rawInstallURL(*vaultURL)), 0o644),
	)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		if out, err := exec.Command("git", "-C", dir, "init", "-q").CombinedOutput(); err != nil {
			return fmt.Errorf("git init: %s", strings.TrimSpace(string(out)))
		}
	}
	_ = exec.Command("git", "-C", dir, "config", "core.hooksPath", ".githooks").Run()
	fmt.Printf("vault created in %s\n  vault.toml, install.sh, personas/, .githooks/pre-commit, .github/workflows/guard.yml\n  next: dfm --vault %s persona new\n", dir, dir)
	return nil
}

// rawInstallURL derives the raw.githubusercontent.com URL of install.sh
// from a GitHub clone URL; other hosts get a placeholder.
func rawInstallURL(cloneURL string) string {
	u := strings.TrimSuffix(cloneURL, ".git")
	if strings.HasPrefix(u, "https://github.com/") {
		return "https://raw.githubusercontent.com/" + strings.TrimPrefix(u, "https://github.com/") + "/main/install.sh"
	}
	return "<raw URL of install.sh in this repo>"
}

const installTemplate = `#!/bin/sh
# Bootstrap: download the dfm release for this machine, verify it, run it
# against this vault. Usage:  curl -fsSL <raw url of this file> | sh
set -eu
TOOL_REPO="__TOOL_REPO__"
VAULT_URL="__VAULT_URL__"
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
exec "$BIN_DIR/dfm" --vault "$VAULT_URL" "$@" </dev/tty
`

const preCommitHook = `#!/bin/sh
# Refuse commits that contain private key material or malformed persona files.
if command -v dfm >/dev/null 2>&1; then
  exec dfm guard --staged
fi
# Fallback without the binary: a conservative text check.
status=0
for f in $(git diff --cached --name-only --diff-filter=ACMR); do
  if git show ":$f" | grep -qE "PRIVATE KEY""-----|AGE-SECRET""-KEY-"; then
    echo "guard: $f contains private key material" >&2; status=1
  fi
  case "$f" in
    personas/*/bundle.age)
      git show ":$f" | head -c 21 | grep -q 'age-encryption.org/v1' || { echo "guard: $f is not age ciphertext" >&2; status=1; } ;;
    personas/*/*) case "$(basename "$f")" in bundle.age|github.pub|admin.pub|persona.env) ;; *) echo "guard: $f is not an allowed persona file" >&2; status=1 ;; esac ;;
    notes-local/*) echo "guard: $f is under notes-local" >&2; status=1 ;;
  esac
done
exit $status
`

const guardWorkflow = `name: guard
on:
  push:
  pull_request:
  schedule:
    - cron: "17 4 * * 1"
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: install dfm
        run: |
          curl -fsSL https://github.com/__TOOL_REPO__/releases/latest/download/dfm-linux-amd64 -o dfm
          curl -fsSL https://github.com/__TOOL_REPO__/releases/latest/download/SHA256SUMS -o SHA256SUMS
          grep " dfm-linux-amd64$" SHA256SUMS | sha256sum -c -
          chmod +x dfm
      - name: guard tracked files
        run: ./dfm guard
      - name: gitleaks over history
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
`

const readmeTemplate = `# SSH key vault

Encrypted SSH keys and machine bootstrap, managed by dfm (dotfile-manager).
Private keys live in personas/<name>/bundle.age, encrypted with age and a passphrase.
Public keys and persona.env are plaintext. Nothing else confidential is committed;
.githooks/pre-commit and the guard workflow enforce that.

## New machine

    curl -fsSL %s | sh

The wizard asks for a persona, the roles for this machine and the passphrase, then does the rest.

## Clone and inspect first

    git clone <this repo> && cd <repo> && sh install.sh
`
