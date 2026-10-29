package guard

import (
	"testing"

	"github.com/JonasHess/dotfile-manager/internal/bundle"
	"github.com/JonasHess/dotfile-manager/internal/keys"
)

func TestGuard(t *testing.T) {
	enc, _ := bundle.Encrypt(bundle.Files{"x": []byte("y")}, []byte("p"))
	pair, _ := keys.Generate("dfm:t:github")

	cases := map[string]struct {
		path    string
		content []byte
		bad     bool
	}{
		"good bundle":      {"personas/t/bundle.age", enc, false},
		"good pub":         {"personas/t/github.pub", pair.Public, false},
		"good env":         {"personas/t/persona.env", []byte("name=t\n"), false},
		"plain bundle":     {"personas/t/bundle.age", []byte("hello"), true},
		"private key":      {"personas/t/bundle.age", pair.Private, true},
		"key in readme":    {"README.md", pair.Private, true},
		"age identity":     {"x.txt", []byte("AGE-SECRET-KEY-1ABC"), true},
		"stray file":       {"personas/t/id_ed25519", []byte("x"), true},
		"nested":           {"personas/t/deep/f", []byte("x"), true},
		"notes-local":      {"notes-local/design.md", []byte("x"), true},
		"bad pub":          {"personas/t/admin.pub", []byte("not a key"), true},
		"ordinary go file": {"internal/x.go", []byte("package x"), false},
	}
	for name, c := range cases {
		got := Check(c.path, c.content)
		if (len(got) > 0) != c.bad {
			t.Errorf("%s: findings=%v want bad=%v", name, got, c.bad)
		}
	}
}
