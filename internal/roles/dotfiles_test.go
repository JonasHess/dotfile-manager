package roles

import "testing"

func TestStowConflictRegexp(t *testing.T) {
	out := `LINK: .zshrc => repos/dotfiles/.zshrc
WARNING! stowing . would cause conflicts:
  * existing target is neither a link nor a directory: .claude/settings.json
  * existing target is not owned by stow: .gitconfig
All operations aborted.`
	m := stowConflictRe.FindAllStringSubmatch(out, -1)
	if len(m) != 2 || m[0][1] != ".claude/settings.json" || m[1][1] != ".gitconfig" {
		t.Fatalf("got %v", m)
	}
}
