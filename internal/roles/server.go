package roles

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/JonasHess/dotfile-manager/internal/authkeys"
	"github.com/JonasHess/dotfile-manager/internal/keys"
	"github.com/JonasHess/dotfile-manager/internal/platform"
	"github.com/JonasHess/dotfile-manager/internal/sshd"
)

// AuthorizedKeysPath returns the authorized_keys file of an account.
func AuthorizedKeysPath(account string) (string, *user.User, error) {
	u, err := user.Lookup(account)
	if err != nil {
		return "", nil, err
	}
	return filepath.Join(u.HomeDir, ".ssh", "authorized_keys"), u, nil
}

// InstallAuthorizedKey adds the persona's admin public key to the accounts.
// Other users' files need root; without it the account is skipped with a
// warning rather than failing the whole run.
func (c *Context) InstallAuthorizedKey(personaName string, adminPub []byte, accounts []string) error {
	fp, _, err := keys.FingerprintOfPublic(adminPub)
	if err != nil {
		return err
	}
	for _, acc := range accounts {
		path, u, err := AuthorizedKeysPath(acc)
		if err != nil {
			c.report(Warn, "account %s: %v", acc, err)
			continue
		}
		if acc != c.Plat.User && !c.Plat.IsRoot {
			c.report(Warn, "account %s: need root to edit %s, skipped", acc, path)
			continue
		}
		f, err := authkeys.Open(path)
		if err != nil {
			return err
		}
		var dropped int
		f.Lines, dropped, err = authkeys.Add(f.Lines, adminPub)
		if err != nil {
			return err
		}
		backup, err := f.Save(c.Paths.BackupDir)
		if err != nil {
			return err
		}
		if c.Plat.IsRoot && acc != c.Plat.User {
			uid, _ := strconv.Atoi(u.Uid)
			gid, _ := strconv.Atoi(u.Gid)
			_ = os.Chown(path, uid, gid)
			_ = os.Chown(filepath.Dir(path), uid, gid)
			_ = os.Chmod(filepath.Dir(path), 0o700)
		}
		switch {
		case backup == "":
			c.report(OK, "%s already has %s (%s)", path, fp, personaName)
		case dropped > 0:
			c.report(OK, "%s: admin key added, %d duplicate line(s) collapsed, backup %s", path, dropped, backup)
		default:
			c.report(OK, "%s: admin key added, backup %s", path, backup)
		}
	}
	c.State.AddRole(personaName, Server)
	return nil
}

// EnsureSSHD makes sure an SSH server runs. It needs root or sudo.
func (c *Context) EnsureSSHD() error {
	run := sshd.Runner{Sudo: !c.Plat.IsRoot}
	if !c.Plat.IsRoot && !c.Plat.HasSudo {
		if sshd.Installed() {
			c.report(Info, "sshd is installed; cannot check or enable the service without root")
			return nil
		}
		return errors.New("no SSH server installed and no root or sudo to install one")
	}
	if sshd.Installed() && runtime.GOOS != "darwin" {
		if out, err := exec.Command("sh", "-c", "systemctl is-active ssh sshd 2>/dev/null | grep -q '^active$'").CombinedOutput(); err == nil {
			c.report(OK, "sshd is installed and active")
			return nil
		} else {
			_ = out
		}
	}
	if err := sshd.EnsureService(run, c.Plat.PkgMgr); err != nil {
		return err
	}
	c.report(OK, "SSH server installed and enabled")
	return nil
}

// ReportSSHD prints the effective settings the wizard cares about.
func (c *Context) ReportSSHD() *sshd.Effective {
	eff, err := sshd.Query(!c.Plat.IsRoot)
	if err != nil {
		c.report(Info, "could not read effective sshd settings: %v", err)
		return nil
	}
	c.report(Info, "sshd: PermitRootLogin %s, PasswordAuthentication %s, port %s", eff.PermitRootLogin, eff.PasswordAuthentication, eff.Port)
	if eff.PasswordAuthentication == "yes" {
		for _, o := range sshd.FindPasswordOverrides() {
			if o.Value == "yes" {
				c.report(Warn, "%s sets PasswordAuthentication yes and wins over sshd_config", o.File)
			}
		}
	}
	return eff
}

// Harden disables password login after the lock-out guard passed.
func (c *Context) Harden(personaName, adminFingerprint string, accounts []string) error {
	if !c.Plat.IsRoot && !c.Plat.HasSudo {
		return errors.New("hardening needs root or sudo")
	}
	if c.WaitEnter == nil {
		c.report(Skip, "hardening needs an interactive run: the new key's login must be proven first")
		return nil
	}
	c.report(Info, "Before password login is switched off, prove the new key works.")
	host := platform.ReachableAddress()
	if host == "" {
		host = c.Plat.Hostname
	}
	acc := c.Plat.User
	if len(accounts) > 0 {
		acc = accounts[0]
	}
	c.report(Info, "From another machine run:  ssh -i ~/.ssh/dfm/%s/id_ed25519_admin %s@%s", personaName, acc, host)
	if c.Plat.IsSSH {
		c.report(Warn, "Your current session came in over SSH. Keep it open until the new login has worked.")
	}
	for {
		if c.WaitEnter == nil || !c.WaitEnter("press enter once you have logged in with the new key, or s to skip hardening") {
			c.report(Skip, "password login left unchanged")
			return nil
		}
		when, ok := ProvenLogin(adminFingerprint, 10*time.Minute)
		if ok {
			c.report(OK, "publickey login with the new key seen at %s", when)
			break
		}
		c.report(Warn, "no publickey login with %s found in the last 10 minutes; not hardening", adminFingerprint)
	}
	run := sshd.Runner{Sudo: !c.Plat.IsRoot}
	if err := sshd.Harden(run); err != nil {
		return err
	}
	c.report(OK, "%s written, sshd validated and reloaded: password login off, root key login kept", sshd.DropIn)
	return nil
}

// ProvenLogin looks for an accepted publickey login with the fingerprint in
// the journal or the auth log within the window.
func ProvenLogin(fingerprint string, window time.Duration) (string, bool) {
	since := fmt.Sprintf("-%dmin", int(window.Minutes()))
	if _, err := exec.LookPath("journalctl"); err == nil {
		out, err := exec.Command("journalctl", "--no-pager", "-o", "short-iso", "--since", since, "-u", "ssh", "-u", "sshd", "-t", "sshd").Output()
		if err == nil {
			if when, ok := scanAccepted(string(out), fingerprint); ok {
				return when, true
			}
		}
	}
	cutoff := time.Now().Add(-window)
	for _, p := range []string{"/var/log/auth.log", "/var/log/secure"} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		st, _ := f.Stat()
		if st != nil && st.ModTime().Before(cutoff) {
			f.Close()
			continue
		}
		var text strings.Builder
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			text.WriteString(sc.Text() + "\n")
		}
		f.Close()
		if when, ok := scanAccepted(text.String(), fingerprint); ok {
			return when, true
		}
	}
	return "", false
}

func scanAccepted(log, fingerprint string) (string, bool) {
	var last string
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, "Accepted publickey") && strings.Contains(line, fingerprint) {
			last = line
		}
	}
	if last == "" {
		return "", false
	}
	f := strings.Fields(last)
	if len(f) > 0 {
		return f[0], true
	}
	return last, true
}
