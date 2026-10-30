// Package vault reads the user's vault repository: a git checkout that
// holds vault.toml and one directory per persona with the encrypted bundle
// and the plaintext public keys.
package vault

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config is the content of vault.toml. Every field is optional.
type Config struct {
	Vault struct {
		Owner string `toml:"owner"` // GitHub account the keys belong to
	} `toml:"vault"`
	Dotfiles struct {
		Repo     string   `toml:"repo"`     // ssh clone URL
		Target   string   `toml:"target"`   // checkout directory, ~ allowed
		Install  string   `toml:"install"`  // command run inside the checkout after cloning
		Packages []string `toml:"packages"` // packages the dotfiles need, installed before Install runs
	} `toml:"dotfiles"`
	Legacy struct {
		AuthorizedKeysComments []string `toml:"authorized_keys_comments"`
		PrivateKeys            []string `toml:"private_keys"`
	} `toml:"legacy"`
}

// Files are the four files that make up a persona in the vault.
var Files = []string{"bundle.age", "github.pub", "admin.pub", "persona.env"}

type Vault struct {
	Dir    string
	Config Config
}

// Persona is the public, unencrypted view of a persona as stored in the vault.
type Persona struct {
	Name      string
	Dir       string
	Bundle    []byte
	GithubPub []byte
	AdminPub  []byte
	Env       map[string]string
}

// Open loads a vault from a directory. vault.toml may be absent.
func Open(dir string) (*Vault, error) {
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return nil, fmt.Errorf("vault directory %s does not exist", dir)
	}
	v := &Vault{Dir: dir}
	cfgPath := filepath.Join(dir, "vault.toml")
	if _, err := os.Stat(cfgPath); err == nil {
		if _, err := toml.DecodeFile(cfgPath, &v.Config); err != nil {
			return nil, fmt.Errorf("vault.toml: %w", err)
		}
	}
	return v, nil
}

// PersonasDir is where personas live inside the vault.
func (v *Vault) PersonasDir() string { return filepath.Join(v.Dir, "personas") }

// List returns the persona names that have a bundle, sorted.
func (v *Vault) List() ([]string, error) {
	entries, err := os.ReadDir(v.PersonasDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(v.PersonasDir(), e.Name(), "bundle.age")); err == nil {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// Load reads one persona's files.
func (v *Vault) Load(name string) (*Persona, error) {
	dir := filepath.Join(v.PersonasDir(), name)
	p := &Persona{Name: name, Dir: dir, Env: map[string]string{}}
	var err error
	if p.Bundle, err = os.ReadFile(filepath.Join(dir, "bundle.age")); err != nil {
		return nil, fmt.Errorf("persona %s: %w", name, err)
	}
	if p.GithubPub, err = os.ReadFile(filepath.Join(dir, "github.pub")); err != nil {
		return nil, fmt.Errorf("persona %s: %w", name, err)
	}
	if p.AdminPub, err = os.ReadFile(filepath.Join(dir, "admin.pub")); err != nil {
		return nil, fmt.Errorf("persona %s: %w", name, err)
	}
	if f, err := os.Open(filepath.Join(dir, "persona.env")); err == nil {
		p.Env = ParseEnv(f)
		f.Close()
	}
	return p, nil
}

// LoadAll loads every persona.
func (v *Vault) LoadAll() ([]*Persona, error) {
	names, err := v.List()
	if err != nil {
		return nil, err
	}
	var out []*Persona
	for _, n := range names {
		p, err := v.Load(n)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// ParseEnv reads key=value lines; '#' starts a comment.
func ParseEnv(r interface{ Read([]byte) (int, error) }) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, val, ok := strings.Cut(line, "=")
		if ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(val)
		}
	}
	return m
}

// FormatEnv writes key=value lines in a stable order.
func FormatEnv(m map[string]string) []byte {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, m[k])
	}
	return []byte(b.String())
}

// DefaultDir is where the tool keeps its checkout of the vault.
func DefaultDir(home string) string {
	return filepath.Join(home, ".local", "share", "dfm", "vault")
}

// Ensure makes sure a vault checkout exists at dir. source may be a git URL
// (cloned when dir is missing) or empty (dir must already exist). An existing
// checkout is fast-forwarded when possible; failures to update are reported
// but not fatal, because the vault may be usable offline.
func Ensure(dir, source string) (*Vault, string, error) {
	var note string
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		if source == "" {
			return nil, "", fmt.Errorf("no vault at %s and no source URL given (use --vault)", dir)
		}
		if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
			return nil, "", err
		}
		cmd := exec.Command("git", "clone", "--quiet", source, dir)
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return nil, "", fmt.Errorf("git clone %s: %w", source, err)
		}
		note = "cloned " + source
	} else if hasUpstream(dir) {
		cmd := exec.Command("git", "-C", dir, "pull", "--ff-only", "--quiet")
		if out, err := cmd.CombinedOutput(); err != nil {
			note = "could not update vault: " + firstLine(string(out))
		} else {
			note = "vault up to date"
		}
	}
	v, err := Open(dir)
	return v, note, err
}

func hasUpstream(dir string) bool {
	return exec.Command("git", "-C", dir, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}").Run() == nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// Remote returns the origin URL of the vault checkout, or empty.
func (v *Vault) Remote() string {
	out, err := exec.Command("git", "-C", v.Dir, "remote", "get-url", "origin").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
