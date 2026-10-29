// Package platform detects the facts about the current machine that the
// wizard needs to make decisions: operating system, CPU, distribution,
// package manager, whether we run as root, inside WSL, over SSH, or headless.
package platform

import (
	"bufio"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
)

type Info struct {
	OS        string // darwin, linux
	Arch      string // amd64, arm64, arm
	Distro    string // ubuntu, debian, raspbian, fedora, arch, alpine, macos, unknown
	Pretty    string // human readable OS name and version
	Hostname  string
	User      string
	Home      string
	IsRoot    bool
	IsWSL     bool
	IsSSH     bool   // the current session arrived over SSH
	HasSudo   bool   // sudo binary exists (not whether it is passwordless)
	Headless  bool   // no graphical session detected
	PkgMgr    string // brew, apt, dnf, pacman, apk, or empty
	AgentSock string // SSH_AUTH_SOCK, empty when no agent is advertised
}

// Detect gathers platform facts. It never fails; unknown facts stay empty.
func Detect() Info {
	in := Info{OS: runtime.GOOS, Arch: runtime.GOARCH}
	in.Hostname, _ = os.Hostname()
	if u, err := user.Current(); err == nil {
		in.User = u.Username
		in.Home = u.HomeDir
		in.IsRoot = u.Uid == "0"
	}
	if h := os.Getenv("HOME"); h != "" {
		in.Home = h
	}
	in.IsSSH = os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != ""
	in.AgentSock = os.Getenv("SSH_AUTH_SOCK")
	_, err := exec.LookPath("sudo")
	in.HasSudo = err == nil

	switch in.OS {
	case "darwin":
		in.Distro = "macos"
		in.Pretty = macosPretty()
		in.PkgMgr = firstOnPath("brew")
		in.Headless = false
	case "linux":
		in.Distro, in.Pretty = osRelease()
		in.IsWSL = detectWSL()
		in.PkgMgr = firstOnPath("apt-get", "dnf", "pacman", "apk")
		if in.PkgMgr == "apt-get" {
			in.PkgMgr = "apt"
		}
		in.Headless = os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == ""
	}
	return in
}

func firstOnPath(names ...string) string {
	for _, n := range names {
		if _, err := exec.LookPath(n); err == nil {
			return n
		}
	}
	return ""
}

func osRelease() (id, pretty string) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "unknown", "Linux"
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "ID":
			id = v
		case "PRETTY_NAME":
			pretty = v
		}
	}
	if id == "" {
		id = "unknown"
	}
	if pretty == "" {
		pretty = id
	}
	return id, pretty
}

func detectWSL() bool {
	b, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	s := strings.ToLower(string(b))
	return strings.Contains(s, "microsoft") || strings.Contains(s, "wsl")
}

func macosPretty() string {
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return "macOS"
	}
	return "macOS " + strings.TrimSpace(string(out))
}

// Summary is the one-line header used by the TUI.
func (i Info) Summary() string {
	parts := []string{i.Hostname, i.Pretty, i.Arch, i.User}
	if i.IsWSL {
		parts = append(parts, "WSL")
	}
	if i.IsSSH {
		parts = append(parts, "ssh session")
	}
	return strings.Join(parts, "  ")
}
