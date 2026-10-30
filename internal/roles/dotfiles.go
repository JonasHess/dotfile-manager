package roles

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
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
		if out, err := exec.Command("git", "-C", target, "submodule", "update", "--init", "--recursive", "--quiet").CombinedOutput(); err != nil {
			c.report(Warn, "git submodule update: %s", strings.TrimSpace(string(out)))
		} else {
			c.report(OK, "submodules up to date")
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
	for _, pkg := range c.Vault.Config.Dotfiles.Packages {
		if _, err := exec.LookPath(pkg); err == nil {
			continue
		}
		if err := c.installPackage(pkg); err != nil {
			c.report(Warn, "%s not installed: %v", pkg, err)
		}
	}
	install := c.Vault.Config.Dotfiles.Install
	if install == "" {
		c.report(Info, "no [dotfiles] install command in vault.toml, nothing else to do")
		return nil
	}
	if strings.Contains(install, "stow") {
		if _, err := exec.LookPath("stow"); err != nil {
			if err := c.installPackage("stow"); err != nil {
				c.report(Warn, "stow is not installed and could not be installed: %v", err)
				return nil
			}
		}
	}
	if !c.confirm(fmt.Sprintf("Run the dotfiles install command now?\n    %s", install), true) {
		return nil
	}
	if strings.Contains(install, "stow ") {
		if err := c.resolveStowConflicts(install, target); err != nil {
			return err
		}
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

var stowConflictRe = regexp.MustCompile(`existing target is (?:neither a link nor a directory|not owned by stow): (.+)`)

// resolveStowConflicts dry-runs the stow command, lists the files in the
// target that would block it, and offers to move them into dfm's backup
// directory so the real run succeeds. Stow never overwrites, so without
// this step the install aborts on the first pre-existing dotfile.
func (c *Context) resolveStowConflicts(install, dir string) error {
	dry := strings.Replace(install, "stow ", "stow -n ", 1)
	cmd := exec.Command("sh", "-c", dry)
	cmd.Dir = dir
	out, _ := cmd.CombinedOutput()
	var conflicts []string
	for _, m := range stowConflictRe.FindAllStringSubmatch(string(out), -1) {
		conflicts = append(conflicts, strings.TrimSpace(m[1]))
	}
	if len(conflicts) == 0 {
		return nil
	}
	c.report(Warn, "stow would stop on %d existing file(s) in %s:", len(conflicts), c.Paths.Home)
	for _, rel := range conflicts {
		c.report(Info, "  %s", filepath.Join(c.Paths.Home, rel))
	}
	backup := filepath.Join(c.Paths.BackupDir, time.Now().Format("20060102-150405"), "dotfiles")
	if !c.confirm(fmt.Sprintf("Move them to %s so stow can link the repo versions?", backup), true) {
		return errors.New("stow conflicts left in place; resolve them and rerun the dotfiles step")
	}
	for _, rel := range conflicts {
		src := filepath.Join(c.Paths.Home, rel)
		dst := filepath.Join(backup, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		if err := os.Rename(src, dst); err != nil {
			return fmt.Errorf("move %s: %w", src, err)
		}
		c.report(OK, "%s moved to %s", src, dst)
	}
	return nil
}

// installPackage installs a package with the detected package manager,
// via sudo when not root. Homebrew refuses to run as root, so it is used
// as the invoking user.
func (c *Context) installPackage(name string) error {
	var args []string
	switch c.Plat.PkgMgr {
	case "brew":
		args = []string{"brew", "install", name}
	case "apt":
		args = []string{"apt-get", "install", "-y", "-qq", name}
	case "dnf":
		args = []string{"dnf", "install", "-y", name}
	case "pacman":
		args = []string{"pacman", "-S", "--noconfirm", name}
	case "apk":
		args = []string{"apk", "add", name}
	default:
		return errors.New("no known package manager")
	}
	if c.Plat.PkgMgr != "brew" && !c.Plat.IsRoot {
		if !c.Plat.HasSudo {
			return errors.New("needs root or sudo")
		}
		args = append([]string{"sudo", "-n"}, args...)
	}
	if !c.confirm(fmt.Sprintf("%s is missing. Install it now?\n    %s", name, strings.Join(args, " ")), true) {
		return errors.New("declined")
	}
	if c.Plat.PkgMgr == "apt" {
		_ = exec.Command(args[0], append(args[1:len(args)-4], "update", "-qq")...).Run()
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	c.report(OK, "%s installed", name)
	return nil
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
