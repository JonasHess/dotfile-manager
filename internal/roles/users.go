package roles

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/JonasHess/dotfile-manager/internal/vault"
)

// SystemBinary is where dfm installs itself when running as root, so that
// setups launched for other accounts find the same version.
const SystemBinary = "/usr/local/bin/dfm"

// HomeUsers lists login accounts with a home under /home or /Users.
func HomeUsers() []string {
	var out []string
	for _, pattern := range []string{"/home/*", "/Users/*"} {
		dirs, _ := filepath.Glob(pattern)
		for _, d := range dirs {
			name := filepath.Base(d)
			if name == "Shared" {
				continue
			}
			if u, err := user.Lookup(name); err == nil && u.HomeDir == d {
				out = append(out, name)
			}
		}
	}
	return out
}

// SetupForUser runs "dfm setup" as another account with the same answers,
// so every file lands in that account's home with that account's ownership.
// The passphrase travels over the child's stdin, never over arguments.
// Running as root uses runuser or su; running as a user uses sudo for root.
func (c *Context) SetupForUser(account string, args []string, passphrase []byte) error {
	target, err := user.Lookup(account)
	if err != nil {
		return err
	}
	bin, err := c.binaryFor(account)
	if err != nil {
		return err
	}
	vaultDir, err := c.vaultFor(target)
	if err != nil {
		return err
	}
	full := append([]string{bin, "--vault", vaultDir, "--yes", "--passphrase-fd", "0", "setup"}, args...)

	var cmd *exec.Cmd
	switch {
	case c.Plat.IsRoot:
		if _, err := exec.LookPath("runuser"); err == nil {
			cmd = exec.Command("runuser", append([]string{"-u", account, "--"}, full...)...)
		} else {
			cmd = exec.Command("su", "-s", "/bin/sh", account, "-c", shellJoin(full))
		}
		cmd.Env = []string{"HOME=" + target.HomeDir, "USER=" + account, "LOGNAME=" + account,
			"PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin", "TERM=" + os.Getenv("TERM")}
	case account == "root":
		if !c.Plat.HasSudo {
			return errors.New("setting up root needs sudo")
		}
		cmd = exec.Command("sudo", append([]string{"-H", "-u", "root", "--"}, full...)...)
		cmd.Env = os.Environ()
	default:
		return fmt.Errorf("setting up %s needs root", account)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	c.report(Info, "running setup as %s in %s", account, target.HomeDir)
	if err := cmd.Start(); err != nil {
		return err
	}
	_, _ = io.WriteString(stdin, string(passphrase)+"\n")
	stdin.Close()
	return cmd.Wait()
}

// binaryFor returns a dfm path the target account can execute. Root copies
// the running binary to SystemBinary; a user handing work to root can let
// root run the user's own copy.
func (c *Context) binaryFor(account string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	self, _ = filepath.EvalSymlinks(self)
	if !c.Plat.IsRoot {
		return self, nil
	}
	if self == SystemBinary {
		return self, nil
	}
	data, err := os.ReadFile(self)
	if err != nil {
		return "", err
	}
	if old, err := os.ReadFile(SystemBinary); err == nil && string(old) == string(data) {
		return SystemBinary, nil
	}
	tmp := SystemBinary + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return "", fmt.Errorf("install %s: %w", SystemBinary, err)
	}
	if err := os.Rename(tmp, SystemBinary); err != nil {
		return "", err
	}
	c.report(OK, "dfm installed system-wide at %s", SystemBinary)
	return SystemBinary, nil
}

// vaultFor makes sure the target account has its own vault checkout. The
// current checkout is copied, because the target may not be able to clone
// yet (a private vault over ssh needs the very key being installed).
func (c *Context) vaultFor(target *user.User) (string, error) {
	dir := vault.DefaultDir(target.HomeDir)
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		return dir, nil
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return "", err
	}
	if out, err := exec.Command("cp", "-a", c.Vault.Dir, dir).CombinedOutput(); err != nil {
		return "", fmt.Errorf("copy vault: %s", strings.TrimSpace(string(out)))
	}
	uid, _ := strconv.Atoi(target.Uid)
	gid, _ := strconv.Atoi(target.Gid)
	for _, p := range []string{filepath.Join(target.HomeDir, ".local"), filepath.Join(target.HomeDir, ".local", "share"), filepath.Join(target.HomeDir, ".local", "share", "dfm")} {
		_ = os.Chown(p, uid, gid)
	}
	err := filepath.Walk(dir, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(p, uid, gid)
	})
	if err != nil {
		return "", err
	}
	c.report(OK, "vault copied to %s", dir)
	return dir, nil
}

func shellJoin(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(q, " ")
}
