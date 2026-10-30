package roles

import (
	"os"
	"path/filepath"
	"time"

	"github.com/JonasHess/dotfile-manager/internal/authkeys"
	"github.com/JonasHess/dotfile-manager/internal/keys"
)

// RemovePersona undoes what setup installed for a persona on this machine:
// its key files go to backup, its admin key leaves the current user's
// authorized_keys (never the last key), the state forgets it and the config
// fragment is regenerated. Other machines are untouched and are reported.
func (c *Context) RemovePersona(name string, adminPub []byte) error {
	if _, ok := c.State.Personas[name]; !ok {
		c.report(Info, "persona %s was not set up on this machine", name)
		return nil
	}
	dir := c.Paths.PersonaDir(name)
	if _, err := os.Stat(dir); err == nil {
		dst := filepath.Join(c.Paths.BackupDir, time.Now().Format("20060102-150405"), name)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		if err := os.Rename(dir, dst); err != nil {
			return err
		}
		c.report(OK, "%s moved to %s", dir, dst)
	}
	if fp, _, err := keys.FingerprintOfPublic(adminPub); err == nil {
		if f, err := authkeys.Open(c.Paths.AuthKeys); err == nil {
			var removed int
			f.Lines, removed, err = authkeys.Remove(f.Lines, authkeys.Match{Fingerprints: []string{fp}}, "")
			if err != nil {
				c.report(Warn, "%s: %v", c.Paths.AuthKeys, err)
			} else if removed > 0 {
				if backup, err := f.Save(c.Paths.BackupDir); err == nil {
					c.report(OK, "%s: admin key removed, backup %s", c.Paths.AuthKeys, backup)
				}
			}
		}
	}
	delete(c.State.Personas, name)
	delete(c.State.Protected, name)
	if c.State.Default == name {
		c.State.Default = ""
		for other, rs := range c.State.Personas {
			if has(rs, Github) {
				c.State.Default = other
				break
			}
		}
		if c.State.Default != "" {
			c.report(Info, "persona %s now owns plain github.com", c.State.Default)
		}
	}
	return c.WriteConfig()
}
