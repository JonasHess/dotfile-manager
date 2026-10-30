package cleanup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JonasHess/dotfile-manager/internal/keys"
	"github.com/JonasHess/dotfile-manager/internal/platform"
	"github.com/JonasHess/dotfile-manager/internal/state"
	"github.com/JonasHess/dotfile-manager/internal/vault"
)

func TestScanAndRemove(t *testing.T) {
	home := t.TempDir()
	paths := state.NewPaths(home)
	os.MkdirAll(paths.SSHDir, 0o700)
	legacy, _ := keys.Generate("MainKey")
	fresh, _ := keys.Generate("dfm:private:admin")
	os.WriteFile(paths.AuthKeys, []byte(strings.Repeat(string(legacy.Public), 3)+string(fresh.Public)), 0o600)
	os.WriteFile(filepath.Join(paths.SSHDir, "id_rsa_JH_Github"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(paths.SSHDir, "id_rsa_JH_Github.pub"), []byte("y"), 0o644)
	os.WriteFile(paths.UserCfg, []byte("Include dfm/config\n\n"+oldInstallerConfig), 0o600)

	v := &vault.Vault{Dir: t.TempDir()}
	v.Config.Legacy.AuthorizedKeysComments = []string{"MainKey"}
	v.Config.Legacy.PrivateKeys = []string{"id_rsa_JH_Github"}
	plat := platform.Info{User: "u"}

	found := Scan(plat, paths, v, nil)
	if len(found) != 3 {
		t.Fatalf("findings: %v", found)
	}
	for _, f := range found {
		if _, err := Remove(f, paths.BackupDir, fresh.Fingerprint); err != nil {
			t.Fatalf("remove %s: %v", f.Path, err)
		}
	}
	b, _ := os.ReadFile(paths.AuthKeys)
	if strings.Contains(string(b), "MainKey") || !strings.Contains(string(b), "dfm:private:admin") {
		t.Fatalf("authorized_keys after cleanup: %q", b)
	}
	if _, err := os.Stat(filepath.Join(paths.SSHDir, "id_rsa_JH_Github")); err == nil {
		t.Fatal("legacy key still present")
	}
	cfg, err := os.ReadFile(paths.UserCfg)
	if err != nil || string(cfg) != "Include dfm/config\n" {
		t.Fatalf("legacy config cleanup must keep the Include line, got %q (%v)", cfg, err)
	}
	if again := Scan(plat, paths, v, nil); len(again) != 0 {
		t.Fatalf("second scan: %v", again)
	}
}
