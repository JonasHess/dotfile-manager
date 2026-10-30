// Package knownhosts pins GitHub's published SSH host keys into
// ~/.ssh/known_hosts instead of trusting whatever answers on first contact.
package knownhosts

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/JonasHess/dotfile-manager/internal/sshconfig"
)

// GitHub host keys as published at https://api.github.com/meta (ssh_keys).
// Fetched 2026-10-29. Update deliberately when GitHub rotates them.
var GitHub = []string{
	"github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
	"github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=",
	"github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=",
}

// PinGitHub appends the GitHub entries that are missing from the file.
// Returns how many lines were added.
func PinGitHub(path string) (int, error) {
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return 0, err
	}
	have := map[string]bool{}
	for _, l := range strings.Split(string(existing), "\n") {
		f := strings.Fields(l)
		if len(f) >= 3 {
			have[f[1]+" "+f[2]] = true
		}
	}
	var add bytes.Buffer
	n := 0
	for _, line := range GitHub {
		f := strings.Fields(line)
		if !have[f[1]+" "+f[2]] {
			add.WriteString(line + "\n")
			n++
		}
	}
	if n == 0 {
		return 0, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return 0, err
	}
	out := existing
	if len(out) > 0 && !bytes.HasSuffix(out, []byte("\n")) {
		out = append(out, '\n')
	}
	out = append(out, add.Bytes()...)
	return n, sshconfig.WriteOwned(path, out, 0o600)
}

// GitHubCallback verifies github.com against the pinned keys only, for the
// in-process connection test.
func GitHubCallback() ssh.HostKeyCallback {
	var pinned []ssh.PublicKey
	for _, line := range GitHub {
		if _, _, pub, _, _, err := ssh.ParseKnownHosts([]byte(line)); err == nil {
			pinned = append(pinned, pub)
		}
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		for _, p := range pinned {
			if bytes.Equal(p.Marshal(), key.Marshal()) {
				return nil
			}
		}
		return errors.New("github.com presented a host key that is not in the pinned set")
	}
}
