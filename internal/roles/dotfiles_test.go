package roles

import (
	"os"
	"path/filepath"
	"testing"
)

func conflictsIn(out string) []string {
	var c []string
	for _, m := range stowConflictRe.FindAllStringSubmatch(out, -1) {
		if m[1] != "" {
			c = append(c, m[1])
		} else {
			c = append(c, m[2])
		}
	}
	return c
}

func TestStowConflictRegexp(t *testing.T) {
	old := `WARNING! stowing . would cause conflicts:
  * existing target is neither a link nor a directory: .claude/settings.json
  * existing target is not owned by stow: .gitconfig
All operations aborted.`
	if c := conflictsIn(old); len(c) != 2 || c[0] != ".claude/settings.json" || c[1] != ".gitconfig" {
		t.Fatalf("stow 2.3 wording: %v", c)
	}
	neu := `WARNING! stowing . would cause conflicts:
  * cannot stow repos/dotfiles/.claude/settings.json over existing target .claude/settings.json since neither a link nor a directory and --adopt not specified
  * cannot stow repos/dotfiles/.gitconfig over existing target .gitconfig since neither a link nor a directory and --adopt not specified
All operations aborted.`
	if c := conflictsIn(neu); len(c) != 2 || c[0] != ".claude/settings.json" || c[1] != ".gitconfig" {
		t.Fatalf("stow 2.4 wording: %v", c)
	}
}

func TestGitIdentityFile(t *testing.T) {
	home := t.TempDir()
	if got := GitIdentityFile(home); got != filepath.Join(home, ".gitconfig") {
		t.Fatalf("plain home: %s", got)
	}
	os.WriteFile(filepath.Join(home, ".gitconfig"), []byte("[include]\n\tpath = ~/.gitconfig.local\n"), 0o644)
	if got := GitIdentityFile(home); got != filepath.Join(home, ".gitconfig.local") {
		t.Fatalf("include: %s", got)
	}
	os.Remove(filepath.Join(home, ".gitconfig"))
	os.Symlink("repos/dotfiles/.gitconfig", filepath.Join(home, ".gitconfig"))
	if got := GitIdentityFile(home); got != filepath.Join(home, ".gitconfig.local") {
		t.Fatalf("symlink: %s", got)
	}
}

func TestHttpsOf(t *testing.T) {
	if got := httpsOf("git@github.com:JonasHess/dotfiles.git"); got != "https://github.com/JonasHess/dotfiles.git" {
		t.Fatal(got)
	}
	if got := httpsOf("https://x/y.git"); got != "https://x/y.git" {
		t.Fatal(got)
	}
}
