// Package doctor checks the machine for the misconfigurations that bite:
// permissions, the config Include, agent state, sshd settings and the
// cloud-init password override, and leftover legacy material.
package doctor

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/JonasHess/dotfile-manager/internal/agent"
	"github.com/JonasHess/dotfile-manager/internal/cleanup"
	"github.com/JonasHess/dotfile-manager/internal/platform"
	"github.com/JonasHess/dotfile-manager/internal/sshconfig"
	"github.com/JonasHess/dotfile-manager/internal/sshd"
	"github.com/JonasHess/dotfile-manager/internal/state"
	"github.com/JonasHess/dotfile-manager/internal/vault"
)

type Level string

const (
	OK   Level = "ok"
	Info Level = "info"
	Warn Level = "warn"
)

type Result struct {
	Level Level
	Text  string
}

func Run(plat platform.Info, paths state.Paths, st *state.State, v *vault.Vault, personas []*vault.Persona) []Result {
	var out []Result
	add := func(l Level, f string, a ...any) { out = append(out, Result{l, fmt.Sprintf(f, a...)}) }

	if st, err := os.Stat(paths.SSHDir); err != nil {
		add(Warn, "%s does not exist", paths.SSHDir)
	} else if m := st.Mode().Perm(); m&0o077 != 0 {
		add(Warn, "%s is %o, should be 700", paths.SSHDir, m)
	} else {
		add(OK, "%s is 700", paths.SSHDir)
	}
	for name := range st.Personas {
		for _, purpose := range []string{"github", "admin"} {
			p := paths.KeyPath(name, purpose)
			if fi, err := os.Stat(p); err == nil && fi.Mode().Perm()&0o077 != 0 {
				add(Warn, "%s is %o, should be 600", p, fi.Mode().Perm())
			}
		}
	}

	needsInclude := st.HasRole("github") || st.HasRole("client")
	if b, err := os.ReadFile(paths.UserCfg); err != nil {
		if needsInclude {
			add(Warn, "%s missing; the generated fragment is not included", paths.UserCfg)
		}
	} else if sshconfig.HasInclude(string(b)) {
		add(OK, "Include dfm/config present at the top of %s", paths.UserCfg)
	} else if needsInclude {
		add(Warn, "%s lacks 'Include dfm/config' before the first Host block", paths.UserCfg)
	}

	switch {
	case agent.Available():
		add(OK, "ssh-agent reachable at %s", plat.AgentSock)
	case len(st.Personas) == 0:
		add(Info, "no ssh-agent running")
	default:
		protected := false
		for _, p := range st.Protected {
			protected = protected || p
		}
		if protected {
			add(Warn, "no ssh-agent running; protected keys will prompt on every connection")
		} else {
			add(Info, "no ssh-agent running; keys here are unprotected by choice")
		}
	}

	if sshd.Installed() {
		eff, err := sshd.Query(!plat.IsRoot)
		if err != nil {
			add(Info, "sshd installed; effective settings unreadable without root (%v)", err)
		} else {
			if eff.PasswordAuthentication == "yes" {
				msg := "password login is ON"
				for _, o := range sshd.FindPasswordOverrides() {
					if o.Value == "yes" {
						msg += fmt.Sprintf(": %s overrides sshd_config (first value wins)", o.File)
					}
				}
				add(Warn, "%s", msg)
			} else {
				add(OK, "password login is off")
			}
			switch eff.PermitRootLogin {
			case "no":
				add(Info, "PermitRootLogin no: root cannot log in over SSH (left as is)")
			case "yes":
				add(Warn, "PermitRootLogin yes: root may log in with a password if one is set")
			default:
				add(OK, "PermitRootLogin %s: root logs in with a key only", eff.PermitRootLogin)
			}
		}
		if _, err := exec.LookPath("systemctl"); err == nil {
			if out, _ := exec.Command("sh", "-c", "systemctl is-active ssh sshd 2>/dev/null").Output(); !strings.Contains(string(out), "active") {
				add(Warn, "sshd is installed but no ssh/sshd service is active")
			}
		}
	} else {
		add(Info, "no SSH server installed")
	}

	if v != nil {
		for _, f := range cleanup.Scan(plat, paths, v, personas) {
			add(Warn, "legacy material: %s", f)
		}
	}
	return out
}
