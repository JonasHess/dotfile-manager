package keys

import (
	"bytes"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGenerateRoundTrip(t *testing.T) {
	p, err := Generate("dfm:test:github")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(p.Public, []byte("ssh-ed25519 ")) || !bytes.HasSuffix(p.Public, []byte(" dfm:test:github\n")) {
		t.Fatalf("unexpected public line %q", p.Public)
	}
	again, err := Parse(p.Private, "dfm:test:github")
	if err != nil {
		t.Fatal(err)
	}
	if again.Fingerprint != p.Fingerprint {
		t.Fatalf("fingerprint changed on parse: %s vs %s", again.Fingerprint, p.Fingerprint)
	}
	fp, comment, err := FingerprintOfPublic(p.Public)
	if err != nil || fp != p.Fingerprint || comment != "dfm:test:github" {
		t.Fatalf("FingerprintOfPublic: %s %s %v", fp, comment, err)
	}
}

func TestProtect(t *testing.T) {
	p, _ := Generate("c")
	enc, err := p.Protect([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ssh.ParseRawPrivateKey(enc); err == nil {
		t.Fatal("protected key parsed without passphrase")
	}
	raw, err := ssh.ParseRawPrivateKeyWithPassphrase(enc, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := ssh.NewSignerFromKey(raw)
	if ssh.FingerprintSHA256(s.PublicKey()) != p.Fingerprint {
		t.Fatal("fingerprint mismatch after protect")
	}
}

func TestWriteFilesRefusesDifferentContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	if err := WriteFiles(path, []byte("a"), []byte("b")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFiles(path, []byte("a"), []byte("b")); err != nil {
		t.Fatalf("same content must be accepted: %v", err)
	}
	if err := WriteFiles(path, []byte("x"), []byte("b")); err == nil {
		t.Fatal("different content must be refused")
	}
}
