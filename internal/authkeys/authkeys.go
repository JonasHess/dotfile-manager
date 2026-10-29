// Package authkeys edits authorized_keys files with the guards that keep a
// machine reachable: deduplication by key, never removing the last key, and
// backups before every change.
package authkeys

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Line is one parsed authorized_keys entry. Raw keeps the original text so
// unknown options survive a rewrite.
type Line struct {
	Raw         string
	Fingerprint string // empty for comments and blank lines
	Comment     string
}

// Parse splits an authorized_keys file into lines.
func Parse(content []byte) []Line {
	var out []Line
	if len(bytes.TrimSpace(content)) == 0 {
		return nil
	}
	for _, raw := range strings.Split(strings.TrimRight(string(content), "\n"), "\n") {
		l := Line{Raw: raw}
		if t := strings.TrimSpace(raw); t != "" && !strings.HasPrefix(t, "#") {
			if pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(t)); err == nil {
				l.Fingerprint = ssh.FingerprintSHA256(pub)
				l.Comment = comment
			}
		}
		out = append(out, l)
	}
	return out
}

// Format joins lines back into file content.
func Format(lines []Line) []byte {
	var b bytes.Buffer
	for _, l := range lines {
		b.WriteString(l.Raw)
		b.WriteString("\n")
	}
	return b.Bytes()
}

// KeyCount is the number of real key lines.
func KeyCount(lines []Line) int {
	n := 0
	for _, l := range lines {
		if l.Fingerprint != "" {
			n++
		}
	}
	return n
}

// Add appends pubLine unless the same key is already present. Duplicate
// copies of the same key are collapsed to one. Returns the new lines and
// how many duplicates were dropped.
func Add(lines []Line, pubLine []byte) ([]Line, int, error) {
	pub, comment, _, _, err := ssh.ParseAuthorizedKey(pubLine)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid public key: %w", err)
	}
	fp := ssh.FingerprintSHA256(pub)
	var out []Line
	seen := false
	dropped := 0
	for _, l := range lines {
		if l.Fingerprint == fp {
			if seen {
				dropped++
				continue
			}
			seen = true
			l = Line{Raw: strings.TrimSpace(string(pubLine)), Fingerprint: fp, Comment: comment}
		}
		out = append(out, l)
	}
	if !seen {
		out = append(out, Line{Raw: strings.TrimSpace(string(pubLine)), Fingerprint: fp, Comment: comment})
	}
	return out, dropped, nil
}

// Match selects lines to remove: by exact comment or by fingerprint.
type Match struct {
	Comments     []string
	Fingerprints []string
}

func (m Match) hits(l Line) bool {
	if l.Fingerprint == "" {
		return false
	}
	for _, c := range m.Comments {
		if c != "" && l.Comment == c {
			return true
		}
	}
	for _, f := range m.Fingerprints {
		if f != "" && l.Fingerprint == f {
			return true
		}
	}
	return false
}

// Find returns the lines that Match selects.
func Find(lines []Line, m Match) []Line {
	var out []Line
	for _, l := range lines {
		if m.hits(l) {
			out = append(out, l)
		}
	}
	return out
}

var ErrLastKey = errors.New("refusing to remove the last authorized key")

// Remove drops matching lines. keep is a fingerprint that must survive (the
// newly installed key); if removal would leave no key at all, ErrLastKey.
func Remove(lines []Line, m Match, keep string) ([]Line, int, error) {
	var out []Line
	removed := 0
	for _, l := range lines {
		if m.hits(l) && l.Fingerprint != keep {
			removed++
			continue
		}
		out = append(out, l)
	}
	if removed > 0 && KeyCount(out) == 0 {
		return nil, 0, ErrLastKey
	}
	return out, removed, nil
}

// File reads, edits and writes one authorized_keys file with a backup.
type File struct {
	Path  string
	Lines []Line
	orig  []byte
}

func Open(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return &File{Path: path, Lines: Parse(b), orig: b}, nil
}

// Save writes the file (0600) after copying the original into backupDir.
// Returns the backup path, empty when nothing changed.
func (f *File) Save(backupDir string) (string, error) {
	content := Format(f.Lines)
	if bytes.Equal(content, f.orig) || (len(f.orig) == 0 && len(f.Lines) == 0) {
		return "", nil
	}
	backup := ""
	if len(f.orig) > 0 {
		if err := os.MkdirAll(backupDir, 0o700); err != nil {
			return "", err
		}
		backup = filepath.Join(backupDir, filepath.Base(f.Path)+"."+time.Now().Format("20060102-150405"))
		if err := os.WriteFile(backup, f.orig, 0o600); err != nil {
			return "", err
		}
	}
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
		return "", err
	}
	tmp := f.Path + ".dfm.tmp"
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, f.Path); err != nil {
		return "", err
	}
	f.orig = content
	return backup, nil
}
