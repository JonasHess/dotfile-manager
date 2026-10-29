// Package roles applies the github, client, server and dotfiles roles to
// this machine. Every step reports what it did through the Context so the
// TUI and the non-interactive mode share one implementation.
package roles

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/JonasHess/dotfile-manager/internal/platform"
	"github.com/JonasHess/dotfile-manager/internal/state"
	"github.com/JonasHess/dotfile-manager/internal/vault"
)

// Role names as stored in state and accepted on the command line.
const (
	Github   = "github"
	Client   = "client"
	Server   = "server"
	Dotfiles = "dotfiles"
)

var All = []string{Github, Client, Server, Dotfiles}

// Status values passed to Report.
const (
	OK   = "ok"
	Warn = "warn"
	Fail = "fail"
	Info = "info"
	Skip = "--"
)

type Context struct {
	Plat    platform.Info
	Paths   state.Paths
	State   *state.State
	Vault   *vault.Vault
	Version string

	// Report prints one progress line.
	Report func(status, format string, args ...any)
	// Confirm asks a yes/no question; non-interactive runs answer def.
	Confirm func(prompt string, def bool) bool
	// WaitEnter blocks until the user presses enter; non-interactive runs return false.
	WaitEnter func(msg string) bool
}

func (c *Context) report(status, format string, args ...any) {
	if c.Report != nil {
		c.Report(status, format, args...)
	}
}

func (c *Context) confirm(prompt string, def bool) bool {
	if c.Confirm == nil {
		return def
	}
	return c.Confirm(prompt, def)
}

// backup moves path into the backup directory and returns the new location.
func (c *Context) backup(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(c.Paths.BackupDir, time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, filepath.Base(path))
	if st.IsDir() {
		return dst, fmt.Errorf("refusing to back up a directory: %s", path)
	}
	return dst, os.Rename(path, dst)
}
