// Package persona creates, unlocks, verifies and rotates personas in a vault.
// A persona is a pair of ed25519 keys (github, admin) stored encrypted in
// one age bundle, plus their public halves in plaintext.
package persona

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/JonasHess/dotfile-manager/internal/bundle"
	"github.com/JonasHess/dotfile-manager/internal/keys"
	"github.com/JonasHess/dotfile-manager/internal/vault"
)

// Purposes are the keys every persona has, in bundle file order.
var Purposes = []string{"github", "admin"}

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,15}$`)

// ValidateName enforces the persona naming rule: it becomes a directory
// name in the vault and under ~/.ssh, so it stays short and lowercase.
func ValidateName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("persona name %q must match %s", name, nameRe)
	}
	return nil
}

// Comment is the public key comment convention; cleanup and dedupe rely on it.
func Comment(persona, purpose string) string {
	return "dfm:" + persona + ":" + purpose
}

// Unlocked holds a persona's decrypted keys in memory.
type Unlocked struct {
	Name     string
	Github   *keys.Pair
	Admin    *keys.Pair
	Manifest map[string]string
}

// Create generates new keys, writes the persona into the vault and verifies
// the written bundle by decrypting it again. It never touches git.
func Create(v *vault.Vault, name string, passphrase []byte, toolVersion string) (*Unlocked, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	dir := filepath.Join(v.PersonasDir(), name)
	if _, err := os.Stat(dir); err == nil {
		return nil, fmt.Errorf("persona %s already exists at %s", name, dir)
	}
	return writeNew(v, name, passphrase, toolVersion, nil)
}

// Rotate replaces both keys of an existing persona. The previous fingerprints
// are recorded as retired so cleanup can recognise them on machines later.
func Rotate(v *vault.Vault, name string, passphrase []byte, toolVersion string) (*Unlocked, error) {
	old, err := v.Load(name)
	if err != nil {
		return nil, err
	}
	if _, err := Unlock(old, passphrase); err != nil {
		return nil, err
	}
	retired := retiredOf(old)
	for _, pub := range [][]byte{old.GithubPub, old.AdminPub} {
		if fp, _, err := keys.FingerprintOfPublic(pub); err == nil {
			retired = append(retired, fp)
		}
	}
	if err := os.RemoveAll(old.Dir); err != nil {
		return nil, err
	}
	return writeNew(v, name, passphrase, toolVersion, retired)
}

// ChangePassphrase re-encrypts the bundle; keys stay the same.
func ChangePassphrase(v *vault.Vault, name string, oldPass, newPass []byte) error {
	p, err := v.Load(name)
	if err != nil {
		return err
	}
	files, err := bundle.Decrypt(p.Bundle, oldPass)
	if err != nil {
		return err
	}
	enc, err := bundle.Encrypt(files, newPass)
	if err != nil {
		return err
	}
	if _, err := bundle.Decrypt(enc, newPass); err != nil {
		return fmt.Errorf("verification after re-encrypt failed: %w", err)
	}
	return os.WriteFile(filepath.Join(p.Dir, "bundle.age"), enc, 0o644)
}

// Unlock decrypts a persona and checks the private keys against the
// plaintext public keys, so a tampered or mismatched vault is caught here.
func Unlock(p *vault.Persona, passphrase []byte) (*Unlocked, error) {
	files, err := bundle.Decrypt(p.Bundle, passphrase)
	if err != nil {
		return nil, err
	}
	u := &Unlocked{Name: p.Name, Manifest: vault.ParseEnv(bytes.NewReader(files["manifest"]))}
	if u.Github, err = loadKey(files, "github", p.Name, p.GithubPub); err != nil {
		return nil, err
	}
	if u.Admin, err = loadKey(files, "admin", p.Name, p.AdminPub); err != nil {
		return nil, err
	}
	return u, nil
}

// Verify is Unlock without keeping the result.
func Verify(p *vault.Persona, passphrase []byte) error {
	_, err := Unlock(p, passphrase)
	return err
}

func loadKey(files bundle.Files, purpose, persona string, pub []byte) (*keys.Pair, error) {
	priv, ok := files["id_ed25519_"+purpose]
	if !ok {
		return nil, fmt.Errorf("bundle has no %s key", purpose)
	}
	pair, err := keys.Parse(priv, Comment(persona, purpose))
	if err != nil {
		return nil, fmt.Errorf("%s key: %w", purpose, err)
	}
	fp, _, err := keys.FingerprintOfPublic(pub)
	if err != nil {
		return nil, fmt.Errorf("%s.pub: %w", purpose, err)
	}
	if fp != pair.Fingerprint {
		return nil, fmt.Errorf("%s key in bundle (%s) does not match %s.pub (%s)", purpose, pair.Fingerprint, purpose, fp)
	}
	return pair, nil
}

func writeNew(v *vault.Vault, name string, passphrase []byte, toolVersion string, retired []string) (*Unlocked, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("empty passphrase")
	}
	gh, err := keys.Generate(Comment(name, "github"))
	if err != nil {
		return nil, err
	}
	ad, err := keys.Generate(Comment(name, "admin"))
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	env := map[string]string{
		"name":               name,
		"created":            now,
		"github_fingerprint": gh.Fingerprint,
		"admin_fingerprint":  ad.Fingerprint,
		"tool_version":       toolVersion,
	}
	if len(retired) > 0 {
		env["retired"] = strings.Join(retired, ",")
	}
	files := bundle.Files{
		"id_ed25519_github": gh.Private,
		"id_ed25519_admin":  ad.Private,
		"manifest":          vault.FormatEnv(env),
	}
	enc, err := bundle.Encrypt(files, passphrase)
	if err != nil {
		return nil, err
	}

	dir := filepath.Join(v.PersonasDir(), name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	write := func(n string, b []byte) error { return os.WriteFile(filepath.Join(dir, n), b, 0o644) }
	if err := errors.Join(
		write("bundle.age", enc),
		write("github.pub", gh.Public),
		write("admin.pub", ad.Public),
		write("persona.env", vault.FormatEnv(env)),
	); err != nil {
		return nil, err
	}

	// Read back and verify exactly what later machines will see.
	p, err := v.Load(name)
	if err != nil {
		return nil, err
	}
	u, err := Unlock(p, passphrase)
	if err != nil {
		return nil, fmt.Errorf("verification of written persona failed: %w", err)
	}
	return u, nil
}

// Delete removes a persona from the vault after checking the passphrase, so
// nobody deletes a persona they cannot open. It never touches git.
func Delete(v *vault.Vault, name string, passphrase []byte) error {
	p, err := v.Load(name)
	if err != nil {
		return err
	}
	if _, err := Unlock(p, passphrase); err != nil {
		return err
	}
	return os.RemoveAll(p.Dir)
}

func retiredOf(p *vault.Persona) []string {
	if r := p.Env["retired"]; r != "" {
		return strings.Split(r, ",")
	}
	return nil
}

// Retired lists fingerprints of keys this persona used before a rotation.
func Retired(p *vault.Persona) []string { return retiredOf(p) }
