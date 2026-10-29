// Package github verifies a key against github.com in-process, the
// equivalent of "ssh -T git@github.com", with host keys pinned.
package github

import (
	"errors"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/JonasHess/dotfile-manager/internal/knownhosts"
)

var hiRe = regexp.MustCompile(`Hi ([^!]+)!`)

// ErrRejected means GitHub did not accept the key: it is not registered.
var ErrRejected = errors.New("github.com does not know this key yet")

// Check connects as git@github.com with the signer. On success it returns
// the GitHub login that owns the key.
func Check(signer ssh.Signer) (string, error) {
	cfg := &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: knownhosts.GitHubCallback(),
		Timeout:         15 * time.Second,
	}
	client, err := ssh.Dial("tcp", "github.com:22", cfg)
	if err != nil {
		if strings.Contains(err.Error(), "unable to authenticate") {
			return "", ErrRejected
		}
		return "", err
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	// GitHub refuses the shell and prints the greeting on stderr; the
	// non-zero exit is expected.
	out, _ := sess.CombinedOutput("")
	if m := hiRe.FindSubmatch(out); m != nil {
		return string(m[1]), nil
	}
	return "", nil
}
