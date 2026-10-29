// Package sshd inspects and adjusts the SSH server: effective settings via
// "sshd -T", presence and activation of the service, and the hardening
// drop-in, always validated before a reload.
package sshd

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// DropIn is where hardening goes. The leading 00 sorts before cloud-init's
// 50-cloud-init.conf; sshd keeps the first value it reads for a keyword,
// so this file wins over any later drop-in and over sshd_config itself,
// which includes the directory at its top.
const DropIn = "/etc/ssh/sshd_config.d/00-dfm.conf"

const dropInContent = `# Written by dfm. Password logins are off; keys only. Root may still log in with a key.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
`

// Effective holds the settings the wizard and doctor care about.
type Effective struct {
	PermitRootLogin        string
	PasswordAuthentication string
	PubkeyAuthentication   string
	Port                   string
	Raw                    map[string]string
}

// Binary finds sshd on PATH or in the usual sbin locations.
func Binary() string {
	if p, err := exec.LookPath("sshd"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd", "/sbin/sshd"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// Installed reports whether an SSH server binary exists.
func Installed() bool { return Binary() != "" }

// Query runs sshd -T, with sudo when not root and available.
func Query(useSudo bool) (*Effective, error) {
	bin := Binary()
	if bin == "" {
		return nil, errors.New("sshd not installed")
	}
	var cmd *exec.Cmd
	if useSudo {
		cmd = exec.Command("sudo", "-n", bin, "-T")
	} else {
		cmd = exec.Command(bin, "-T")
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("sshd -T: %w", err)
	}
	return parse(out), nil
}

func parse(out []byte) *Effective {
	e := &Effective{Raw: map[string]string{}}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), " ")
		if !ok {
			continue
		}
		e.Raw[strings.ToLower(k)] = v
	}
	e.PermitRootLogin = e.Raw["permitrootlogin"]
	e.PasswordAuthentication = e.Raw["passwordauthentication"]
	e.PubkeyAuthentication = e.Raw["pubkeyauthentication"]
	e.Port = e.Raw["port"]
	return e
}

// Override describes a drop-in that sets PasswordAuthentication before the
// main config gets a chance, the pattern cloud images ship with.
type Override struct {
	File  string
	Value string
}

// FindPasswordOverrides lists drop-ins that set PasswordAuthentication.
func FindPasswordOverrides() []Override {
	var out []Override
	matches, _ := filepath.Glob("/etc/ssh/sshd_config.d/*.conf")
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && strings.EqualFold(f[0], "PasswordAuthentication") {
				out = append(out, Override{File: m, Value: f[1]})
			}
		}
	}
	return out
}

// Harden writes the drop-in, validates with sshd -t and reloads. On a
// validation failure the file is removed again and nothing is reloaded.
func Harden(run Runner) error {
	if runtime.GOOS == "darwin" {
		return errors.New("hardening is not implemented for macOS sshd; use System Settings")
	}
	if err := run.WriteFile(DropIn, []byte(dropInContent), 0o644); err != nil {
		return err
	}
	if out, err := run.Cmd(Binary(), "-t"); err != nil {
		_ = run.Remove(DropIn)
		return fmt.Errorf("sshd -t rejected the configuration, drop-in removed: %s", strings.TrimSpace(string(out)))
	}
	return Reload(run)
}

// Reload asks the service manager to reload sshd without dropping sessions.
func Reload(run Runner) error {
	for _, args := range [][]string{
		{"systemctl", "reload", "ssh"},
		{"systemctl", "reload", "sshd"},
		{"rc-service", "sshd", "reload"},
		{"service", "ssh", "reload"},
		{"service", "sshd", "reload"},
	} {
		if _, err := exec.LookPath(args[0]); err != nil {
			continue
		}
		if _, err := run.Cmd(args[0], args[1:]...); err == nil {
			return nil
		}
	}
	return errors.New("could not reload sshd with systemctl, rc-service or service")
}

// EnsureService installs and enables an SSH server where one is missing.
func EnsureService(run Runner, pkgMgr string) error {
	if runtime.GOOS == "darwin" {
		_, err := run.Cmd("systemsetup", "-setremotelogin", "on")
		return err
	}
	if !Installed() {
		var args []string
		switch pkgMgr {
		case "apt":
			if _, err := run.Cmd("apt-get", "update", "-qq"); err != nil {
				return err
			}
			args = []string{"apt-get", "install", "-y", "-qq", "openssh-server"}
		case "dnf":
			args = []string{"dnf", "install", "-y", "openssh-server"}
		case "pacman":
			args = []string{"pacman", "-S", "--noconfirm", "openssh"}
		case "apk":
			args = []string{"apk", "add", "openssh-server"}
		default:
			return errors.New("no SSH server installed and no known package manager")
		}
		if out, err := run.Cmd(args[0], args[1:]...); err != nil {
			return fmt.Errorf("%s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
		}
	}
	for _, unit := range []string{"ssh", "sshd"} {
		if _, err := exec.LookPath("systemctl"); err == nil {
			if _, err := run.Cmd("systemctl", "enable", "--now", unit); err == nil {
				return nil
			}
		}
		if _, err := exec.LookPath("rc-update"); err == nil {
			if _, err := run.Cmd("rc-update", "add", unit, "default"); err == nil {
				_, _ = run.Cmd("rc-service", unit, "start")
				return nil
			}
		}
	}
	return errors.New("could not enable the ssh service")
}

// Runner executes privileged operations, directly as root or via sudo.
type Runner struct{ Sudo bool }

func (r Runner) Cmd(name string, args ...string) ([]byte, error) {
	if r.Sudo {
		args = append([]string{"-n", name}, args...)
		name = "sudo"
	}
	return exec.Command(name, args...).CombinedOutput()
}

func (r Runner) WriteFile(path string, content []byte, mode os.FileMode) error {
	if !r.Sudo {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		return os.WriteFile(path, content, mode)
	}
	cmd := exec.Command("sudo", "-n", "sh", "-c", fmt.Sprintf("mkdir -p %q && cat > %q && chmod %o %q", filepath.Dir(path), path, mode, path))
	cmd.Stdin = bytes.NewReader(content)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", path, strings.TrimSpace(string(out)))
	}
	return nil
}

func (r Runner) Remove(path string) error {
	if !r.Sudo {
		return os.Remove(path)
	}
	_, err := r.Cmd("rm", "-f", path)
	return err
}
