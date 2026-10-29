package roles

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Dotfiles clones the vault's dotfiles repo and runs its install command.
// With a github role on this machine the ssh URL works; otherwise the user
// is offered a read-only https clone.
func (c *Context) Dotfiles() error {
	repo := c.Vault.Config.Dotfiles.Repo
	if repo == "" {
		return errors.New("vault.toml has no [dotfiles] repo")
	}
	target := c.Vault.Config.Dotfiles.Target
	if target == "" {
		target = "~/repos/dotfiles"
	}
	target = expandHome(target, c.Paths.Home)
	if !c.State.HasRole(Github) && strings.HasPrefix(repo, "git@") {
		https := "https://" + strings.TrimSuffix(strings.Replace(strings.TrimPrefix(repo, "git@"), ":", "/", 1), ".git")
		if !c.confirm(fmt.Sprintf("No github role on this machine. Clone read-only via %s instead?", https), true) {
			return errors.New("dotfiles skipped")
		}
		repo = https
	}
	if _, err := os.Stat(filepath.Join(target, ".git")); err == nil {
		c.report(OK, "%s already exists, pulling", target)
		if out, err := exec.Command("git", "-C", target, "pull", "--ff-only", "--quiet").CombinedOutput(); err != nil {
			c.report(Warn, "git pull: %s", strings.TrimSpace(string(out)))
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		cmd := exec.Command("git", "clone", "--quiet", "--recurse-submodules", repo, target)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("git clone %s: %w", repo, err)
		}
		c.report(OK, "cloned %s to %s", repo, target)
	}
	install := c.Vault.Config.Dotfiles.Install
	if install == "" {
		c.report(Info, "no [dotfiles] install command in vault.toml, nothing else to do")
		return nil
	}
	if strings.Contains(install, "stow") {
		if _, err := exec.LookPath("stow"); err != nil {
			c.report(Warn, "stow is not installed; install it with %s and rerun", stowHint(c.Plat.PkgMgr))
			return nil
		}
	}
	if !c.confirm(fmt.Sprintf("Run the dotfiles install command now?\n    %s", install), true) {
		return nil
	}
	cmd := exec.Command("sh", "-c", install)
	cmd.Dir = target
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("install command failed: %w", err)
	}
	c.report(OK, "dotfiles installed")
	return nil
}

func stowHint(pkg string) string {
	switch pkg {
	case "brew":
		return "brew install stow"
	case "apt":
		return "apt-get install stow"
	case "dnf":
		return "dnf install stow"
	case "pacman":
		return "pacman -S stow"
	case "apk":
		return "apk add stow"
	}
	return "your package manager"
}

func expandHome(p, home string) string {
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}

// GitIdentity sets the global git user.name and user.email.
func (c *Context) GitIdentity(name, email string) error {
	if name == "" && email == "" {
		return nil
	}
	if name != "" {
		if out, err := exec.Command("git", "config", "--global", "user.name", name).CombinedOutput(); err != nil {
			return fmt.Errorf("git config user.name: %s", strings.TrimSpace(string(out)))
		}
	}
	if email != "" {
		if out, err := exec.Command("git", "config", "--global", "user.email", email).CombinedOutput(); err != nil {
			return fmt.Errorf("git config user.email: %s", strings.TrimSpace(string(out)))
		}
	}
	c.report(OK, "git identity set to %s <%s>", name, email)
	return nil
}

// CurrentGitIdentity reads the existing global values, for prefilling.
func CurrentGitIdentity() (name, email string) {
	n, _ := exec.Command("git", "config", "--global", "user.name").Output()
	e, _ := exec.Command("git", "config", "--global", "user.email").Output()
	return strings.TrimSpace(string(n)), strings.TrimSpace(string(e))
}
