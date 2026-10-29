package sshconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	out := Render([]Entry{
		{Persona: "work", GithubKey: "/k/work/gh", AdminKey: "/k/work/admin"},
		{Persona: "private", GithubKey: "/k/private/gh"},
	}, "private", true)
	for _, want := range []string{
		"Host github.com\n  User git\n  IdentityFile /k/private/gh",
		"Host github.com-work\n  HostName github.com\n  User git\n  IdentityFile /k/work/gh",
		"Host *\n  IdentityFile /k/work/admin",
		"UseKeychain yes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(Render(nil, "", false), "Host") {
		t.Error("empty entries must render no Host blocks")
	}
}

func TestEnsureInclude(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	os.WriteFile(cfg, []byte("Host foo\n  User bar\n"), 0o600)
	changed, err := EnsureInclude(cfg)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	b, _ := os.ReadFile(cfg)
	if !strings.HasPrefix(string(b), IncludeLine+"\n\nHost foo") {
		t.Fatalf("got %q", b)
	}
	changed, _ = EnsureInclude(cfg)
	if changed {
		t.Fatal("second run must be a no-op")
	}
	if HasInclude("Host x\n" + IncludeLine) {
		t.Fatal("include after a Host block must not count")
	}
}
