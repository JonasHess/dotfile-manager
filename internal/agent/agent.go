// Package agent loads keys into the running ssh-agent and, on macOS, into
// the keychain so the passphrase is remembered across reboots.
package agent

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

// Available reports whether an agent socket is advertised and answers.
func Available() bool {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return false
	}
	c, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// Add loads an unencrypted private key into the agent. lifetime 0 means
// until the agent exits; a short lifetime is used for one-off operations
// like pushing the vault with a key that is not installed on this machine.
func Add(rawPrivate interface{}, comment string, lifetime time.Duration) error {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return errors.New("no ssh-agent (SSH_AUTH_SOCK is empty)")
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		return fmt.Errorf("ssh-agent: %w", err)
	}
	defer c.Close()
	return agent.NewClient(c).Add(agent.AddedKey{
		PrivateKey:   rawPrivate,
		Comment:      comment,
		LifetimeSecs: uint32(lifetime / time.Second),
	})
}

// AddFileToKeychain runs ssh-add for a protected key file on macOS so the
// passphrase lands in the login keychain. The user is prompted once by
// ssh-add itself. On other systems it is a no-op.
func AddFileToKeychain(path string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	cmd := exec.Command("ssh-add", "--apple-use-keychain", path)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// ShellSnippet is appended to the shell rc on Linux systems without a
// session agent (WSL, headless boxes a person logs in to). It starts one
// agent per machine and reuses it across terminals.
const ShellSnippet = `
# dfm: reuse one ssh-agent across terminals
if [ -z "$SSH_AUTH_SOCK" ] || ! ssh-add -l >/dev/null 2>&1; then
  if [ -r "$HOME/.ssh/dfm/agent.env" ]; then . "$HOME/.ssh/dfm/agent.env" >/dev/null; fi
  if ! ssh-add -l >/dev/null 2>&1; then
    ssh-agent -s > "$HOME/.ssh/dfm/agent.env"; . "$HOME/.ssh/dfm/agent.env" >/dev/null
  fi
fi
`
