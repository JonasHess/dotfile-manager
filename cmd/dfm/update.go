package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/JonasHess/dotfile-manager/internal/ui"
)

// toolRepo publishes the release binaries that "dfm update" installs.
const toolRepo = "JonasHess/dotfile-manager"

// cmdUpdate replaces the running binary with the latest release after
// verifying its SHA-256 against the published SHA256SUMS, the same check
// install.sh performs.
func cmdUpdate() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, _ = filepath.EvalSymlinks(self)
	asset := fmt.Sprintf("dfm-%s-%s", runtime.GOOS, runtime.GOARCH)
	base := "https://github.com/" + toolRepo + "/releases/latest/download/"
	client := &http.Client{Timeout: 2 * time.Minute}

	sums, err := fetch(client, base+"SHA256SUMS")
	if err != nil {
		return err
	}
	expected := ""
	for _, line := range strings.Split(string(sums), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[1] == asset {
			expected = f[0]
		}
	}
	if expected == "" {
		return fmt.Errorf("no checksum for %s in the latest release", asset)
	}
	bin, err := fetch(client, base+asset)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(bin)
	if hex.EncodeToString(sum[:]) != expected {
		return errors.New("checksum mismatch, update aborted")
	}
	tmp := self + ".new"
	if err := os.WriteFile(tmp, bin, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, self); err != nil {
		os.Remove(tmp)
		return err
	}
	ui.Report("ok", "%s updated to the latest release (was %s)", self, version)
	return nil
}

func fetch(c *http.Client, url string) ([]byte, error) {
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
