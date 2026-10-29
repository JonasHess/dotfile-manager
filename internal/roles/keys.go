package roles

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/JonasHess/dotfile-manager/internal/agent"
	"github.com/JonasHess/dotfile-manager/internal/github"
	"github.com/JonasHess/dotfile-manager/internal/keys"
	"github.com/JonasHess/dotfile-manager/internal/knownhosts"
	"github.com/JonasHess/dotfile-manager/internal/persona"
	"github.com/JonasHess/dotfile-manager/internal/sshconfig"
)

// InstallKeys writes the private keys the chosen roles need, regenerates
// the ssh config fragment and loads the keys into the agent. passphrase is
// used to protect the on-disk copies when protected is true.
func (c *Context) InstallKeys(u *persona.Unlocked, roles []string, protected bool, passphrase []byte) error {
	want := map[string]*keys.Pair{}
	if has(roles, Github) {
		want["github"] = u.Github
	}
	if has(roles, Client) {
		want["admin"] = u.Admin
	}
	for purpose, pair := range want {
		path := c.Paths.KeyPath(u.Name, purpose)
		priv := pair.Private
		if protected {
			var err error
			if priv, err = pair.Protect(passphrase); err != nil {
				return err
			}
		}
		if err := c.writeKey(path, priv, pair.Public, pair.Fingerprint); err != nil {
			return err
		}
		mode := "unprotected"
		if protected {
			mode = "protected"
		}
		c.report(OK, "%s written (%s)", path, mode)
	}
	for _, r := range roles {
		if r != Dotfiles {
			c.State.AddRole(u.Name, r)
		}
	}
	c.State.Protected[u.Name] = protected
	if has(roles, Github) && c.State.Default == "" {
		c.State.Default = u.Name
	}
	if err := c.WriteConfig(); err != nil {
		return err
	}
	if has(roles, Github) {
		n, err := knownhosts.PinGitHub(c.Paths.KnownHost)
		if err != nil {
			return err
		}
		c.report(OK, "github.com host keys pinned in %s (%d added)", c.Paths.KnownHost, n)
	}
	c.loadAgent(u, want, protected)
	return nil
}

// writeKey installs a key file, moving a differing existing file to backup.
func (c *Context) writeKey(path string, priv, pub []byte, fp string) error {
	if old, err := os.ReadFile(path + ".pub"); err == nil {
		if oldFp, _, err := keys.FingerprintOfPublic(old); err == nil && oldFp != fp {
			for _, p := range []string{path, path + ".pub"} {
				if dst, err := c.backup(p); err == nil {
					c.report(Warn, "%s had a different key (%s), moved to %s", p, oldFp, dst)
				}
			}
		}
	}
	// A protected copy differs from the unprotected one byte for byte, so
	// an existing file of the same key is replaced rather than compared.
	_ = os.Remove(path)
	return keys.WriteFiles(path, priv, pub)
}

// WriteConfig regenerates ~/.ssh/dfm/config from the state and ensures the
// Include line in ~/.ssh/config.
func (c *Context) WriteConfig() error {
	var entries []sshconfig.Entry
	for name, rs := range c.State.Personas {
		e := sshconfig.Entry{Persona: name}
		if has(rs, Github) {
			e.GithubKey = c.Paths.KeyPath(name, "github")
		}
		if has(rs, Client) {
			e.AdminKey = c.Paths.KeyPath(name, "admin")
		}
		entries = append(entries, e)
	}
	content := sshconfig.Render(entries, c.State.Default, runtime.GOOS == "darwin")
	if err := sshconfig.WriteFragment(c.Paths.Config, content); err != nil {
		return err
	}
	changed, err := sshconfig.EnsureInclude(c.Paths.UserCfg)
	if err != nil {
		return err
	}
	if changed {
		c.report(OK, "%s regenerated, Include line added to %s", c.Paths.Config, c.Paths.UserCfg)
	} else {
		c.report(OK, "%s regenerated, Include present in %s", c.Paths.Config, c.Paths.UserCfg)
	}
	return nil
}

func (c *Context) loadAgent(u *persona.Unlocked, want map[string]*keys.Pair, protected bool) {
	if !agent.Available() {
		if protected {
			c.report(Warn, "no ssh-agent running: you will be asked for the passphrase on every connection until one runs")
			c.offerShellAgent()
		} else {
			c.report(Info, "no ssh-agent running; keys are unprotected so none is needed")
		}
		return
	}
	for purpose, pair := range want {
		if protected && runtime.GOOS == "darwin" {
			if err := agent.AddFileToKeychain(c.Paths.KeyPath(u.Name, purpose)); err != nil {
				c.report(Warn, "ssh-add --apple-use-keychain failed for %s: %v", purpose, err)
				continue
			}
			c.report(OK, "%s key stored in the macOS keychain", purpose)
			continue
		}
		raw, err := pair.RawPrivate()
		if err != nil {
			continue
		}
		if err := agent.Add(raw, pair.Comment, 0); err != nil {
			c.report(Warn, "could not add %s key to ssh-agent: %v", purpose, err)
			continue
		}
		c.report(OK, "%s key loaded into ssh-agent", purpose)
	}
}

// offerShellAgent appends the agent snippet to the shell rc on request.
func (c *Context) offerShellAgent() {
	if runtime.GOOS == "darwin" {
		return
	}
	rc := filepath.Join(c.Paths.Home, ".zshrc")
	if _, err := os.Stat(rc); err != nil {
		rc = filepath.Join(c.Paths.Home, ".bashrc")
	}
	if b, err := os.ReadFile(rc); err == nil && strings.Contains(string(b), "dfm: reuse one ssh-agent") {
		return
	}
	if !c.confirm(fmt.Sprintf("Add an ssh-agent starter to %s so new terminals reuse one agent?", rc), true) {
		return
	}
	f, err := os.OpenFile(rc, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		c.report(Warn, "could not edit %s: %v", rc, err)
		return
	}
	defer f.Close()
	f.WriteString(agent.ShellSnippet)
	c.report(OK, "agent starter appended to %s (takes effect in new shells)", rc)
}

// VerifyGithub tests the persona's GitHub key against github.com and helps
// the user register it when GitHub rejects it. Returns the GitHub login.
func (c *Context) VerifyGithub(u *persona.Unlocked) (string, error) {
	for attempt := 1; ; attempt++ {
		login, err := github.Check(u.Github.Signer())
		if err == nil {
			c.report(OK, "ssh -T git@github.com: Hi %s!", login)
			return login, nil
		}
		if err != github.ErrRejected {
			c.report(Fail, "github.com: %v", err)
			return "", err
		}
		c.report(Warn, "GitHub does not know this key yet. Add it at https://github.com/settings/ssh/new")
		c.report(Info, "%s", strings.TrimSpace(string(u.Github.Public)))
		if c.WaitEnter == nil || !c.WaitEnter("press enter to retry, or s to skip") {
			return "", err
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func has(roles []string, r string) bool {
	for _, x := range roles {
		if x == r {
			return true
		}
	}
	return false
}
