// Package keys generates ed25519 SSH key pairs and writes them in OpenSSH
// format, with or without a passphrase.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Pair holds one generated key pair. Private is the OpenSSH PEM text without
// passphrase; callers that store it on disk protected must call Protect.
type Pair struct {
	Comment     string
	Private     []byte // OpenSSH private key, unencrypted
	Public      []byte // "ssh-ed25519 AAAA... comment\n"
	Fingerprint string // SHA256:...
	signer      ssh.Signer
}

// Generate creates a fresh ed25519 key pair with the given comment.
func Generate(comment string) (*Pair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	return &Pair{
		Comment:     comment,
		Private:     pem.EncodeToMemory(block),
		Public:      authorizedLine(sshPub, comment),
		Fingerprint: ssh.FingerprintSHA256(sshPub),
		signer:      signer,
	}, nil
}

// Parse loads an unencrypted OpenSSH private key. The comment is supplied
// by the caller because x/crypto drops it when parsing.
func Parse(private []byte, comment string) (*Pair, error) {
	raw, err := ssh.ParseRawPrivateKey(private)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return nil, err
	}
	return &Pair{
		Comment:     comment,
		Private:     private,
		Public:      authorizedLine(signer.PublicKey(), comment),
		Fingerprint: ssh.FingerprintSHA256(signer.PublicKey()),
		signer:      signer,
	}, nil
}

// Signer returns the key as an ssh.Signer for in-process connections.
func (p *Pair) Signer() ssh.Signer { return p.signer }

// RawPrivate returns the crypto private key, needed to hand it to ssh-agent.
func (p *Pair) RawPrivate() (interface{}, error) {
	return ssh.ParseRawPrivateKey(p.Private)
}

// Protect returns the private key re-encoded with a passphrase.
func (p *Pair) Protect(passphrase []byte) ([]byte, error) {
	raw, err := ssh.ParseRawPrivateKey(p.Private)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(raw, p.Comment, passphrase)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

// WriteFiles writes <path> (0600) and <path>.pub (0644). An existing file
// with different content is an error; callers back it up first.
func WriteFiles(path string, private, public []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := writeExclusive(path, private, 0o600); err != nil {
		return err
	}
	return writeExclusive(path+".pub", public, 0o644)
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	if old, err := os.ReadFile(path); err == nil {
		if string(old) == string(data) {
			return os.Chmod(path, mode)
		}
		return fmt.Errorf("%s exists with different content", path)
	}
	return os.WriteFile(path, data, mode)
}

// FingerprintOfPublic parses an authorized_keys style line and returns its
// SHA256 fingerprint and comment.
func FingerprintOfPublic(line []byte) (fp, comment string, err error) {
	pub, comment, _, _, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		return "", "", err
	}
	return ssh.FingerprintSHA256(pub), comment, nil
}

func authorizedLine(pub ssh.PublicKey, comment string) []byte {
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if comment != "" {
		line += " " + comment
	}
	return []byte(line + "\n")
}
