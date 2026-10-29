// Package guard is the secret guard shared by the tool, the pre-commit hook
// and CI. It refuses anything that must never land in a public vault.
package guard

import (
	"bytes"
	"fmt"
	"path"
	"strings"

	"github.com/JonasHess/dotfile-manager/internal/bundle"
	"github.com/JonasHess/dotfile-manager/internal/keys"
)

// Finding describes one refused file.
type Finding struct {
	Path   string
	Reason string
}

func (f Finding) String() string { return f.Path + ": " + f.Reason }

var allowedPersonaFiles = map[string]bool{
	"bundle.age": true, "github.pub": true, "admin.pub": true, "persona.env": true,
}

var secretMarkers = [][]byte{
	[]byte("PRIVATE KEY-----"),
	[]byte("AGE-SECRET-KEY-"),
}

// Check inspects one file by its repo-relative path and content.
func Check(relPath string, content []byte) []Finding {
	var out []Finding
	rel := path.Clean(strings.ReplaceAll(relPath, "\\", "/"))
	add := func(reason string) { out = append(out, Finding{Path: rel, Reason: reason}) }

	if strings.HasPrefix(rel, "notes-local/") {
		add("notes-local is never committed")
	}
	for _, m := range secretMarkers {
		if bytes.Contains(content, m) {
			add("contains private key material (" + string(m) + ")")
		}
	}
	if strings.HasPrefix(rel, "personas/") {
		parts := strings.Split(rel, "/")
		if len(parts) != 3 {
			add("unexpected nesting under personas/")
			return out
		}
		name := parts[2]
		if !allowedPersonaFiles[name] {
			add("not one of the allowed persona files")
		}
		switch {
		case name == "bundle.age" && !bundle.IsAge(content):
			add("bundle.age is not age ciphertext")
		case strings.HasSuffix(name, ".pub"):
			if _, _, err := keys.FingerprintOfPublic(content); err != nil {
				add("not a valid public key: " + err.Error())
			}
		}
	}
	return out
}

// CheckAll runs Check over many files.
func CheckAll(files map[string][]byte) []Finding {
	var out []Finding
	for p, c := range files {
		out = append(out, Check(p, c)...)
	}
	return out
}

// Summary formats findings for the terminal.
func Summary(fs []Finding) string {
	if len(fs) == 0 {
		return "guard: ok"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "guard: %d problem(s)\n", len(fs))
	for _, f := range fs {
		b.WriteString("  " + f.String() + "\n")
	}
	return b.String()
}
