package authkeys

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JonasHess/dotfile-manager/internal/keys"
)

func TestAddDedupesAndRemoveGuards(t *testing.T) {
	a, _ := keys.Generate("MainKey")
	b, _ := keys.Generate("dfm:private:admin")
	content := strings.Repeat(string(a.Public), 3) + "# comment\n"
	lines := Parse([]byte(content))
	if KeyCount(lines) != 3 {
		t.Fatalf("count %d", KeyCount(lines))
	}
	lines, dropped, err := Add(lines, b.Public)
	if err != nil || dropped != 0 || KeyCount(lines) != 4 {
		t.Fatalf("add: dropped=%d count=%d err=%v", dropped, KeyCount(lines), err)
	}
	lines, dropped, _ = Add(lines, b.Public)
	if dropped != 0 || KeyCount(lines) != 4 {
		t.Fatal("re-adding must be a no-op")
	}
	lines, dropped, _ = Add(lines, a.Public)
	if dropped != 2 || KeyCount(lines) != 2 {
		t.Fatalf("adding an existing triple key must collapse it: dropped=%d count=%d", dropped, KeyCount(lines))
	}
	found := Find(lines, Match{Comments: []string{"MainKey"}})
	if len(found) != 1 {
		t.Fatalf("find: %d", len(found))
	}
	out, removed, err := Remove(lines, Match{Comments: []string{"MainKey"}}, b.Fingerprint)
	if err != nil || removed != 1 || KeyCount(out) != 1 {
		t.Fatalf("remove: %d %v", removed, err)
	}
	_, _, err = Remove(out, Match{Fingerprints: []string{b.Fingerprint}}, "")
	if !errors.Is(err, ErrLastKey) {
		t.Fatalf("expected ErrLastKey, got %v", err)
	}
	_, removed, err = Remove(out, Match{Fingerprints: []string{b.Fingerprint}}, b.Fingerprint)
	if err != nil || removed != 0 {
		t.Fatal("keep fingerprint must protect the key")
	}
	if !strings.Contains(string(Format(out)), "# comment") {
		t.Fatal("comment line lost")
	}
}

func TestFileSaveBackup(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "authorized_keys")
	a, _ := keys.Generate("x")
	os.WriteFile(p, a.Public, 0o600)
	f, _ := Open(p)
	b, _ := keys.Generate("y")
	f.Lines, _, _ = Add(f.Lines, b.Public)
	backup, err := f.Save(filepath.Join(dir, "backup"))
	if err != nil || backup == "" {
		t.Fatalf("backup=%q err=%v", backup, err)
	}
	bb, _ := os.ReadFile(backup)
	if string(bb) != string(a.Public) {
		t.Fatal("backup content wrong")
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if again, _ := f.Save(filepath.Join(dir, "backup")); again != "" {
		t.Fatal("unchanged save must not back up")
	}
}
