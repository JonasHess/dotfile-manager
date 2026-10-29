package knownhosts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinGitHub(t *testing.T) {
	p := filepath.Join(t.TempDir(), "known_hosts")
	os.WriteFile(p, []byte("example.org ssh-ed25519 AAAA\n"+GitHub[0]), 0o600)
	n, err := PinGitHub(p)
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	b, _ := os.ReadFile(p)
	if strings.Count(string(b), "github.com ") != 3 || !strings.HasPrefix(string(b), "example.org") {
		t.Fatalf("got %q", b)
	}
	if n, _ := PinGitHub(p); n != 0 {
		t.Fatal("second run must add nothing")
	}
}
