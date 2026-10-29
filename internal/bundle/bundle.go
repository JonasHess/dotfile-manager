// Package bundle packs a persona's private keys into a tar archive and
// encrypts it with an age scrypt passphrase recipient.
package bundle

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"filippo.io/age"
)

// Header is the first line of every age file; the guard relies on it.
const Header = "age-encryption.org/v1"

// WorkFactor is the scrypt cost exponent. 18 means about one second per
// passphrase guess on a laptop, which is the point of using scrypt.
const WorkFactor = 18

// Files maps a name inside the bundle to its content.
type Files map[string][]byte

// Encrypt packs files and encrypts them with the passphrase.
func Encrypt(files Files, passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("empty passphrase")
	}
	recipient, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		return nil, err
	}
	recipient.SetWorkFactor(WorkFactor)

	var out bytes.Buffer
	w, err := age.Encrypt(&out, recipient)
	if err != nil {
		return nil, err
	}
	if err := writeTar(w, files); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Decrypt reverses Encrypt. A wrong passphrase yields ErrWrongPassphrase.
func Decrypt(data, passphrase []byte) (Files, error) {
	identity, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(data), identity)
	if err != nil {
		var incorrect *age.NoIdentityMatchError
		if errors.As(err, &incorrect) {
			return nil, ErrWrongPassphrase
		}
		return nil, err
	}
	return readTar(r)
}

var ErrWrongPassphrase = errors.New("wrong passphrase")

// IsAge reports whether data starts with the age header.
func IsAge(data []byte) bool {
	return strings.HasPrefix(string(data), Header+"\n")
}

func writeTar(w io.Writer, files Files) error {
	tw := tar.NewWriter(w)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		hdr := &tar.Header{Name: n, Mode: 0o600, Size: int64(len(files[n]))}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(files[n]); err != nil {
			return err
		}
	}
	return tw.Close()
}

func readTar(r io.Reader) (Files, error) {
	tr := tar.NewReader(r)
	files := Files{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return files, nil
		}
		if err != nil {
			return nil, fmt.Errorf("bundle is not a tar archive: %w", err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		files[hdr.Name] = b
	}
}
