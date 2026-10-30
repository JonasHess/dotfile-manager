package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/JonasHess/dotfile-manager/internal/agent"
	"github.com/JonasHess/dotfile-manager/internal/github"
	"github.com/JonasHess/dotfile-manager/internal/guard"
	"github.com/JonasHess/dotfile-manager/internal/persona"
	"github.com/JonasHess/dotfile-manager/internal/ui"
	"github.com/JonasHess/dotfile-manager/internal/vault"
	"github.com/JonasHess/dotfile-manager/internal/words"
)

func (a *app) cmdPersona(args []string) error {
	sub := "list"
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	name := ""
	if len(args) > 0 {
		name = args[0]
	}
	switch sub {
	case "list":
		return a.personaList()
	case "new":
		if name == "" {
			if a.yes {
				return errors.New("persona new needs a NAME")
			}
			_, err := a.personaNewInteractive()
			return err
		}
		return a.personaNew(name)
	case "verify":
		return a.personaVerify(name)
	case "rotate":
		return a.personaRotate(name)
	case "passphrase":
		return a.personaPassphrase(name)
	case "publish":
		return a.publish(name, "update persona files")
	case "delete":
		return a.personaDelete(name)
	}
	return fmt.Errorf("unknown persona command %q", sub)
}

func (a *app) personasMenu() error {
	for {
		ui.Section("Personas")
		if err := a.personaList(); err != nil {
			return err
		}
		fmt.Println()
		choice, err := ui.Select("Action", []ui.Option{
			{Key: "new", Label: "Create a new persona"},
			{Key: "verify", Label: "Verify a persona", Hint: "decrypt and compare with the public keys"},
			{Key: "rotate", Label: "Rotate keys", Hint: "new keys, old ones marked retired for cleanup"},
			{Key: "passphrase", Label: "Change passphrase", Hint: "re-encrypt, keys unchanged"},
			{Key: "delete", Label: "Delete persona", Hint: "remove from vault and from this machine"},
			{Key: "back", Label: "Back"},
		})
		if err != nil || choice == "back" {
			return nil
		}
		switch choice {
		case "new":
			_, err = a.personaNewInteractive()
		default:
			name, perr := a.pickPersona()
			if perr != nil {
				return perr
			}
			switch choice {
			case "verify":
				err = a.personaVerify(name)
			case "rotate":
				err = a.personaRotate(name)
			case "passphrase":
				err = a.personaPassphrase(name)
			case "delete":
				err = a.personaDelete(name)
			}
		}
		if err != nil {
			ui.Report("fail", "%v", err)
		}
	}
}

func (a *app) pickPersona() (string, error) {
	names, err := a.vault.List()
	if err != nil {
		return "", err
	}
	if len(names) == 0 {
		return "", errors.New("no personas in the vault yet")
	}
	var opts []ui.Option
	for _, n := range names {
		opts = append(opts, ui.Option{Key: n, Label: n})
	}
	return ui.Select("Persona", opts)
}

func (a *app) personaList() error {
	personas, err := a.vault.LoadAll()
	if err != nil {
		return err
	}
	if len(personas) == 0 {
		ui.Report("info", "no personas yet in %s", a.vault.Dir)
		return nil
	}
	var rows [][]string
	for _, p := range personas {
		rows = append(rows, []string{p.Name, "github " + p.Env["github_fingerprint"], "admin " + p.Env["admin_fingerprint"], "created " + day(p.Env["created"])})
	}
	ui.Table(rows)
	return nil
}

// personaNewInteractive asks for name and passphrase, then creates and
// offers to publish.
func (a *app) personaNewInteractive() (*persona.Unlocked, error) {
	ui.Section("Create persona  (1/2)")
	name, err := ui.Input("Name", "", func(s string) error {
		if err := persona.ValidateName(strings.TrimSpace(s)); err != nil {
			return errors.New("lowercase letters, digits, dash; 2 to 16 characters")
		}
		if _, err := os.Stat(filepath.Join(a.vault.PersonasDir(), strings.TrimSpace(s))); err == nil {
			return errors.New("already exists")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	mode, err := ui.Select("Passphrase", []ui.Option{
		{Key: "generate", Label: "generate six random words for me", Hint: fmt.Sprintf("about %d bits from a %d word list", 62, words.Count())},
		{Key: "own", Label: "type my own", Hint: "at least 16 characters recommended"},
	})
	if err != nil {
		return nil, err
	}
	var pass []byte
	if mode == "generate" {
		pass = []byte(words.Passphrase(6))
		fmt.Printf("\n Generated passphrase, write it down now, it is shown once:\n\n     %s\n\n", ui.Bold(string(pass)))
		if !ui.WaitEnter("press enter once you have stored it") {
			return nil, errors.New("cancelled")
		}
	} else {
		pass, err = a.newPassphrase()
		if err != nil {
			return nil, err
		}
	}
	return a.createPersona(name, pass)
}

func (a *app) newPassphrase() ([]byte, error) {
	for {
		p1, err := ui.Passphrase("New passphrase")
		if err != nil {
			return nil, err
		}
		if ui.PassphraseFD >= 0 {
			return p1, nil
		}
		if len(p1) < 12 {
			ui.Report("warn", "shorter than 12 characters; age uses scrypt but the passphrase still carries the weight")
			if !ui.Confirm("Use it anyway?", false) {
				continue
			}
		}
		p2, err := ui.Passphrase("Repeat passphrase")
		if err != nil {
			return nil, err
		}
		if string(p1) != string(p2) {
			ui.Report("fail", "passphrases differ, try again")
			continue
		}
		return p1, nil
	}
}

func (a *app) personaNew(name string) error {
	if a.yes && ui.PassphraseFD < 0 {
		return errors.New("persona new needs a passphrase: run without --yes or pass --passphrase-fd")
	}
	pass, err := a.newPassphrase()
	if err != nil {
		return err
	}
	_, err = a.createPersona(name, pass)
	return err
}

func (a *app) createPersona(name string, pass []byte) (*persona.Unlocked, error) {
	ui.Section("Create persona  (2/2)")
	u, err := persona.Create(a.vault, name, pass, version)
	if err != nil {
		return nil, err
	}
	ui.Report("ok", "id_ed25519_github generated   %s", u.Github.Fingerprint)
	ui.Report("ok", "id_ed25519_admin generated    %s", u.Admin.Fingerprint)
	ui.Report("ok", "bundle encrypted, decrypted again, fingerprints match")
	ui.Report("ok", "%s written: %s", filepath.Join(a.vault.PersonasDir(), name), strings.Join(vault.Files, " "))
	fmt.Println()
	ui.Report("info", "Add the GitHub key to your account:  https://github.com/settings/ssh/new")
	ui.Report("info", "%s", strings.TrimSpace(string(u.Github.Public)))
	if a.ctx.Confirm != nil {
		if err := a.publishWith(u, fmt.Sprintf("persona %s - add encrypted key bundle", name)); err != nil {
			ui.Report("warn", "%v", err)
		}
	}
	return u, nil
}

func (a *app) personaVerify(name string) error {
	p, err := a.vault.Load(name)
	if err != nil {
		return err
	}
	u, _, err := a.unlock(p)
	if err != nil {
		return err
	}
	ui.Report("ok", "github %s matches github.pub", u.Github.Fingerprint)
	ui.Report("ok", "admin  %s matches admin.pub", u.Admin.Fingerprint)
	if fs := a.guardPersona(name); len(fs) > 0 {
		return errors.New(guard.Summary(fs))
	}
	ui.Report("ok", "guard: persona files are clean")
	return nil
}

func (a *app) personaRotate(name string) error {
	p, err := a.vault.Load(name)
	if err != nil {
		return err
	}
	_, pass, err := a.unlock(p)
	if err != nil {
		return err
	}
	if a.ctx.Confirm != nil && !ui.Confirm(fmt.Sprintf("Replace both keys of %q? Machines keep working until you rerun setup on them.", name), false) {
		return errors.New("cancelled")
	}
	u, err := persona.Rotate(a.vault, name, pass, version)
	if err != nil {
		return err
	}
	ui.Report("ok", "new github key %s", u.Github.Fingerprint)
	ui.Report("ok", "new admin key  %s", u.Admin.Fingerprint)
	ui.Report("info", "old fingerprints recorded as retired; cleanup on each machine will offer to remove them")
	ui.Report("info", "register the new GitHub key: %s", strings.TrimSpace(string(u.Github.Public)))
	if a.ctx.Confirm != nil {
		return a.publishWith(u, fmt.Sprintf("persona %s - rotate keys", name))
	}
	return nil
}

func (a *app) personaPassphrase(name string) error {
	p, err := a.vault.Load(name)
	if err != nil {
		return err
	}
	u, old, err := a.unlock(p)
	if err != nil {
		return err
	}
	neu, err := a.newPassphrase()
	if err != nil {
		return err
	}
	if err := persona.ChangePassphrase(a.vault, name, old, neu); err != nil {
		return err
	}
	ui.Report("ok", "bundle re-encrypted with the new passphrase")
	if a.ctx.Confirm != nil {
		return a.publishWith(u, fmt.Sprintf("persona %s - change passphrase", name))
	}
	return nil
}

// personaDelete removes a persona from the vault and from this machine,
// then offers to publish the removal. The GitHub key and other machines
// are the user's job and are spelled out.
func (a *app) personaDelete(name string) error {
	if name == "" {
		return errors.New("persona delete needs a NAME")
	}
	p, err := a.vault.Load(name)
	if err != nil {
		return err
	}
	_, pass, err := a.unlock(p)
	if err != nil {
		return err
	}
	ui.Section(fmt.Sprintf("Delete persona %q", name))
	ui.Report("warn", "other machines keep this persona's keys and still trust its admin key until you run cleanup there")
	ui.Report("warn", "the GitHub key %s must be removed by hand at https://github.com/settings/keys", p.Env["github_fingerprint"])
	if a.ctx.Confirm != nil && !ui.Confirm(fmt.Sprintf("Delete %q from the vault and from this machine?", name), false) {
		return errors.New("cancelled")
	}
	if err := a.ctx.RemovePersona(name, p.AdminPub); err != nil {
		return err
	}
	if err := persona.Delete(a.vault, name, pass); err != nil {
		return err
	}
	ui.Report("ok", "%s removed from the vault", filepath.Join(a.vault.PersonasDir(), name))
	if err := a.save(); err != nil {
		return err
	}
	if a.ctx.Confirm != nil {
		return a.publishRemoval(name)
	}
	return nil
}

// publishRemoval commits the deleted persona directory and offers a push.
func (a *app) publishRemoval(name string) error {
	rel := "personas/" + name
	message := fmt.Sprintf("persona %s - delete", name)
	fmt.Printf("\n commit message:  %s\n\n", message)
	choice, err := ui.Select("Publish", []ui.Option{
		{Key: "push", Label: "Commit and push now"},
		{Key: "commit", Label: "Commit only, I push myself"},
		{Key: "none", Label: "Do nothing, I handle git myself"},
	})
	if err != nil || choice == "none" {
		return nil
	}
	git := func(args ...string) error {
		cmd := exec.Command("git", append([]string{"-C", a.vault.Dir}, args...)...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		return cmd.Run()
	}
	if err := git("add", "-A", "--", rel); err != nil {
		return err
	}
	if err := git("commit", "--quiet", "-m", message, "--", rel); err != nil {
		return fmt.Errorf("git commit: %w", err)
	}
	ui.Report("ok", "committed")
	if choice == "push" {
		if err := git("push", "--quiet", "origin", "HEAD"); err != nil {
			return fmt.Errorf("git push: %w", err)
		}
		ui.Report("ok", "pushed")
	}
	return nil
}

func (a *app) guardPersona(name string) []guard.Finding {
	dir := filepath.Join(a.vault.PersonasDir(), name)
	files := map[string][]byte{}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err == nil {
			files["personas/"+name+"/"+e.Name()] = b
		}
	}
	return guard.CheckAll(files)
}

// publish commits and pushes a persona directory using an already
// installed key or whatever git finds; publishWith uses the persona's own
// GitHub key through the agent so a fresh laptop can push too.
func (a *app) publish(name, message string) error {
	if name == "" {
		return errors.New("persona publish needs a NAME")
	}
	return a.publishWith(&persona.Unlocked{Name: name}, message)
}

func (a *app) publishWith(u *persona.Unlocked, message string) error {
	name := u.Name
	ui.Section(fmt.Sprintf("Publish persona %q", name))
	if u.Github != nil {
		for {
			login, err := github.Check(u.Github.Signer())
			if err == nil {
				ui.Report("ok", "github.com accepts the new key: Hi %s!", login)
				break
			}
			if !errors.Is(err, github.ErrRejected) {
				ui.Report("warn", "github.com: %v", err)
				break
			}
			ui.Report("warn", "GitHub does not know the key yet; add it at https://github.com/settings/ssh/new")
			if !ui.WaitEnter("press enter to retry, or s to continue without") {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	findings := a.guardPersona(name)
	rel := "personas/" + name
	var rows [][]string
	entries, _ := os.ReadDir(filepath.Join(a.vault.Dir, rel))
	for _, e := range entries {
		fi, _ := e.Info()
		status := "ok"
		for _, f := range findings {
			if strings.HasSuffix(f.Path, "/"+e.Name()) {
				status = f.Reason
			}
		}
		rows = append(rows, []string{rel + "/" + e.Name(), fmt.Sprintf("%d B", fi.Size()), status})
	}
	ui.Table(rows)
	if len(findings) > 0 {
		return errors.New("guard refused the persona files; nothing committed")
	}
	fmt.Printf("\n commit message:  %s\n\n", message)
	choice, err := ui.Select("Publish", []ui.Option{
		{Key: "push", Label: "Commit and push now"},
		{Key: "commit", Label: "Commit only, I push myself"},
		{Key: "none", Label: "Do nothing, I handle git myself"},
	})
	if err != nil || choice == "none" {
		return nil
	}
	git := func(args ...string) error {
		cmd := exec.Command("git", append([]string{"-C", a.vault.Dir}, args...)...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		return cmd.Run()
	}
	if err := git("add", "--", rel); err != nil {
		return err
	}
	if err := git("commit", "--quiet", "-m", message, "--", rel); err != nil {
		return fmt.Errorf("git commit: %w", err)
	}
	ui.Report("ok", "committed")
	if choice != "push" {
		return nil
	}
	if remote := a.vault.Remote(); strings.HasPrefix(remote, "https://github.com/") {
		sshURL := "git@github.com:" + strings.TrimPrefix(remote, "https://github.com/")
		if !strings.HasSuffix(sshURL, ".git") {
			sshURL += ".git"
		}
		if err := git("remote", "set-url", "origin", sshURL); err == nil {
			ui.Report("ok", "origin switched to %s", sshURL)
		}
	}
	cleanupKey, err := a.lendGithubKey(u)
	if err != nil {
		ui.Report("warn", "%v; pushing with whatever key ssh finds", err)
	}
	defer cleanupKey()
	if err := git("push", "--quiet", "origin", "HEAD"); err != nil {
		return fmt.Errorf("git push: %w", err)
	}
	ui.Report("ok", "pushed")
	return nil
}

// lendGithubKey makes the persona's GitHub key available for one push:
// through the agent with a ten minute lifetime, or via a 0600 temp file
// and GIT_SSH_COMMAND when no agent runs. The returned func undoes it.
func (a *app) lendGithubKey(u *persona.Unlocked) (func(), error) {
	noop := func() {}
	if u.Github == nil {
		return noop, nil
	}
	if agent.Available() {
		raw, err := u.Github.RawPrivate()
		if err != nil {
			return noop, err
		}
		if err := agent.Add(raw, u.Github.Comment, 10*time.Minute); err != nil {
			return noop, err
		}
		ui.Report("ok", "GitHub key lent to ssh-agent for 10 minutes")
		return noop, nil
	}
	dir, err := os.MkdirTemp("", "dfm-push-")
	if err != nil {
		return noop, err
	}
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, u.Github.Private, 0o600); err != nil {
		return noop, err
	}
	os.Setenv("GIT_SSH_COMMAND", fmt.Sprintf("ssh -i %s -o IdentitiesOnly=yes", keyPath))
	ui.Report("ok", "GitHub key written to a temporary file for this push")
	return func() {
		os.Unsetenv("GIT_SSH_COMMAND")
		os.RemoveAll(dir)
	}, nil
}
