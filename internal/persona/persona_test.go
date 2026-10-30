package persona

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/JonasHess/dotfile-manager/internal/vault"
)

func newVault(t *testing.T) *vault.Vault {
	dir := t.TempDir()
	v, err := vault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCreateUnlockRotate(t *testing.T) {
	v := newVault(t)
	u, err := Create(v, "private", []byte("pw"), "test")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range vault.Files {
		if _, err := os.Stat(filepath.Join(v.PersonasDir(), "private", f)); err != nil {
			t.Fatalf("missing %s", f)
		}
	}
	names, _ := v.List()
	if len(names) != 1 || names[0] != "private" {
		t.Fatalf("list: %v", names)
	}
	p, _ := v.Load("private")
	if p.Env["github_fingerprint"] != u.Github.Fingerprint {
		t.Fatal("persona.env fingerprint mismatch")
	}
	if _, err := Unlock(p, []byte("wrong")); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	if _, err := Create(v, "private", []byte("pw"), "test"); err == nil {
		t.Fatal("duplicate persona accepted")
	}

	r, err := Rotate(v, "private", []byte("pw"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if r.Github.Fingerprint == u.Github.Fingerprint {
		t.Fatal("rotate kept the key")
	}
	p2, _ := v.Load("private")
	ret := Retired(p2)
	if len(ret) != 2 || ret[0] != u.Github.Fingerprint || ret[1] != u.Admin.Fingerprint {
		t.Fatalf("retired: %v", ret)
	}

	if err := ChangePassphrase(v, "private", []byte("pw"), []byte("new")); err != nil {
		t.Fatal(err)
	}
	p3, _ := v.Load("private")
	if err := Verify(p3, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := Verify(p3, []byte("pw")); err == nil {
		t.Fatal("old passphrase still works")
	}
}

func TestTamperedPublicKeyDetected(t *testing.T) {
	v := newVault(t)
	if _, err := Create(v, "work", []byte("pw"), "test"); err != nil {
		t.Fatal(err)
	}
	other := newVault(t)
	Create(other, "work", []byte("pw"), "test")
	o, _ := other.Load("work")
	os.WriteFile(filepath.Join(v.PersonasDir(), "work", "admin.pub"), o.AdminPub, 0o644)
	p, _ := v.Load("work")
	if _, err := Unlock(p, []byte("pw")); err == nil {
		t.Fatal("swapped admin.pub not detected")
	}
}

func TestDelete(t *testing.T) {
	v := newVault(t)
	if _, err := Create(v, "gone", []byte("pw"), "test"); err != nil {
		t.Fatal(err)
	}
	if err := Delete(v, "gone", []byte("wrong")); err == nil {
		t.Fatal("delete with wrong passphrase accepted")
	}
	if err := Delete(v, "gone", []byte("pw")); err != nil {
		t.Fatal(err)
	}
	if names, _ := v.List(); len(names) != 0 {
		t.Fatalf("still listed: %v", names)
	}
}

func TestValidateName(t *testing.T) {
	for _, ok := range []string{"private", "work", "a1", "my-persona"} {
		if err := ValidateName(ok); err != nil {
			t.Errorf("%s rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "A", "1a", "Work", "has space", "toolongnameforthis-x", "a_b"} {
		if err := ValidateName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
