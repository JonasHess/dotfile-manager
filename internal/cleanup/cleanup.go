// Package cleanup finds material from earlier setups on this machine: keys
// listed in the vault's legacy section and keys retired by a rotation. It
// only reports; removal is a separate, confirmed step with backups.
package cleanup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/JonasHess/dotfile-manager/internal/authkeys"
	"github.com/JonasHess/dotfile-manager/internal/platform"
	"github.com/JonasHess/dotfile-manager/internal/state"
	"github.com/JonasHess/dotfile-manager/internal/vault"
)

type Kind int

const (
	AuthorizedLines Kind = iota // lines in an authorized_keys file
	PrivateKeyFile              // a legacy private key (and its .pub)
	LegacyConfig                // the four-line ~/.ssh/config of the old installer
)

type Finding struct {
	Kind   Kind
	Path   string
	Detail string
	match  authkeys.Match
	files  []string
}

func (f Finding) String() string { return f.Path + "    " + f.Detail }

// The exact ~/.ssh/config the old SSH_Public_Key installer wrote. Matching
// the whole content means a user-edited config is never touched.
const oldInstallerConfig = "Host github.com\n  User git\n  Hostname github.com\n  IdentityFile ~/.ssh/id_rsa_JH_Github\n"

// Scan looks for legacy material for the current user and, when root, for
// root and every account under /home.
func Scan(plat platform.Info, paths state.Paths, v *vault.Vault, personas []*vault.Persona) []Finding {
	m := authkeys.Match{Comments: v.Config.Legacy.AuthorizedKeysComments}
	for _, p := range personas {
		m.Fingerprints = append(m.Fingerprints, strings.Split(p.Env["retired"], ",")...)
	}
	var out []Finding
	for _, akPath := range authorizedKeysFiles(plat, paths) {
		f, err := authkeys.Open(akPath)
		if err != nil {
			continue
		}
		hits := authkeys.Find(f.Lines, m)
		if len(hits) == 0 {
			continue
		}
		var comments []string
		for _, h := range hits {
			comments = append(comments, h.Comment)
		}
		out = append(out, Finding{
			Kind: AuthorizedLines, Path: akPath,
			Detail: fmt.Sprintf("%d line(s): %s", len(hits), strings.Join(uniq(comments), ", ")),
			match:  m,
		})
	}
	for _, name := range v.Config.Legacy.PrivateKeys {
		p := filepath.Join(paths.SSHDir, name)
		if _, err := os.Stat(p); err == nil {
			f := Finding{Kind: PrivateKeyFile, Path: p, Detail: "legacy private key", files: []string{p}}
			if _, err := os.Stat(p + ".pub"); err == nil {
				f.files = append(f.files, p+".pub")
				f.Detail += " plus .pub"
			}
			out = append(out, f)
		}
	}
	if b, err := os.ReadFile(paths.UserCfg); err == nil {
		body := strings.TrimPrefix(string(b), "Include dfm/config\n\n")
		if body == oldInstallerConfig {
			out = append(out, Finding{Kind: LegacyConfig, Path: paths.UserCfg, Detail: "4-line config written by the old installer", files: []string{paths.UserCfg}})
		}
	}
	return out
}

// Remove applies one finding with backups. keep is the fingerprint of the
// newly installed admin key that must never be removed.
func Remove(f Finding, backupDir, keep string) (string, error) {
	switch f.Kind {
	case AuthorizedLines:
		file, err := authkeys.Open(f.Path)
		if err != nil {
			return "", err
		}
		var removed int
		file.Lines, removed, err = authkeys.Remove(file.Lines, f.match, keep)
		if err != nil {
			return "", err
		}
		backup, err := file.Save(backupDir)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d line(s) removed, backup %s", removed, backup), nil
	case PrivateKeyFile, LegacyConfig:
		dir := filepath.Join(backupDir, time.Now().Format("20060102-150405"))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		for _, p := range f.files {
			if err := os.Rename(p, filepath.Join(dir, filepath.Base(p))); err != nil {
				return "", err
			}
		}
		return "moved to " + dir, nil
	}
	return "", nil
}

func authorizedKeysFiles(plat platform.Info, paths state.Paths) []string {
	files := []string{paths.AuthKeys}
	if !plat.IsRoot {
		return files
	}
	homes, _ := filepath.Glob("/home/*/.ssh/authorized_keys")
	files = append(files, homes...)
	if plat.OS == "darwin" {
		users, _ := filepath.Glob("/Users/*/.ssh/authorized_keys")
		files = append(files, users...)
	}
	return uniq(files)
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
