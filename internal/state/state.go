// Package state records what the tool installed on this machine, so later
// runs and the doctor can report it. It lives at ~/.ssh/dfm/state.env.
package state

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/JonasHess/dotfile-manager/internal/vault"
)

// Dir is the directory under ~/.ssh that the tool owns.
const Dir = "dfm"

// Paths resolves the tool's locations under a home directory.
type Paths struct {
	Home      string
	SSHDir    string // ~/.ssh
	ToolDir   string // ~/.ssh/dfm
	Config    string // ~/.ssh/dfm/config (generated fragment)
	State     string // ~/.ssh/dfm/state.env
	BackupDir string // ~/.ssh/dfm/backup
	UserCfg   string // ~/.ssh/config
	AuthKeys  string // ~/.ssh/authorized_keys
	KnownHost string // ~/.ssh/known_hosts
}

func NewPaths(home string) Paths {
	ssh := filepath.Join(home, ".ssh")
	tool := filepath.Join(ssh, Dir)
	return Paths{
		Home: home, SSHDir: ssh, ToolDir: tool,
		Config:    filepath.Join(tool, "config"),
		State:     filepath.Join(tool, "state.env"),
		BackupDir: filepath.Join(tool, "backup"),
		UserCfg:   filepath.Join(ssh, "config"),
		AuthKeys:  filepath.Join(ssh, "authorized_keys"),
		KnownHost: filepath.Join(ssh, "known_hosts"),
	}
}

// PersonaDir is where a persona's keys live on this machine.
func (p Paths) PersonaDir(name string) string { return filepath.Join(p.ToolDir, name) }

// KeyPath is the private key path for a persona and purpose.
func (p Paths) KeyPath(name, purpose string) string {
	return filepath.Join(p.PersonaDir(name), "id_ed25519_"+purpose)
}

// State is the machine record. Roles are stored per persona.
type State struct {
	Version   string
	LastRun   string
	Vault     string              // vault directory used
	Personas  map[string][]string // persona -> roles
	Protected map[string]bool     // persona -> keys protected on disk
	Default   string              // persona that owns plain github.com
}

func Load(path string) *State {
	s := &State{Personas: map[string][]string{}, Protected: map[string]bool{}}
	f, err := os.Open(path)
	if err != nil {
		return s
	}
	defer f.Close()
	for k, v := range vault.ParseEnv(f) {
		switch {
		case k == "version":
			s.Version = v
		case k == "last_run":
			s.LastRun = v
		case k == "vault":
			s.Vault = v
		case k == "default_github":
			s.Default = v
		case strings.HasPrefix(k, "persona.") && strings.HasSuffix(k, ".roles"):
			name := strings.TrimSuffix(strings.TrimPrefix(k, "persona."), ".roles")
			if v != "" {
				s.Personas[name] = strings.Split(v, ",")
			}
		case strings.HasPrefix(k, "persona.") && strings.HasSuffix(k, ".protected"):
			name := strings.TrimSuffix(strings.TrimPrefix(k, "persona."), ".protected")
			s.Protected[name] = v == "true"
		}
	}
	return s
}

func (s *State) Save(path, version string) error {
	s.Version = version
	s.LastRun = time.Now().UTC().Format(time.RFC3339)
	m := map[string]string{"version": s.Version, "last_run": s.LastRun, "vault": s.Vault, "default_github": s.Default}
	for name, roles := range s.Personas {
		m["persona."+name+".roles"] = strings.Join(roles, ",")
		m["persona."+name+".protected"] = map[bool]string{true: "true", false: "false"}[s.Protected[name]]
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, vault.FormatEnv(m), 0o600)
}

// AddRole records a role for a persona without duplicates.
func (s *State) AddRole(persona, role string) {
	for _, r := range s.Personas[persona] {
		if r == role {
			return
		}
	}
	s.Personas[persona] = append(s.Personas[persona], role)
}

// HasRole reports whether any persona has the role.
func (s *State) HasRole(role string) bool {
	for _, roles := range s.Personas {
		for _, r := range roles {
			if r == role {
				return true
			}
		}
	}
	return false
}

// Summary is the status line for the main menu.
func (s *State) Summary() string {
	if len(s.Personas) == 0 {
		return "Nothing installed yet"
	}
	var parts []string
	for name, roles := range s.Personas {
		parts = append(parts, name+" ("+strings.Join(roles, ", ")+")")
	}
	line := "Installed here: " + strings.Join(parts, ", ")
	if s.LastRun != "" {
		line += "    last run " + s.LastRun[:10]
	}
	return line
}
