package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/JonasHess/dotfile-manager/internal/cleanup"
	"github.com/JonasHess/dotfile-manager/internal/doctor"
	"github.com/JonasHess/dotfile-manager/internal/persona"
	"github.com/JonasHess/dotfile-manager/internal/roles"
	"github.com/JonasHess/dotfile-manager/internal/ui"
	"github.com/JonasHess/dotfile-manager/internal/vault"
)

// setupOptions are the answers of the machine setup wizard.
type setupOptions struct {
	persona       string
	roles         []string
	protected     bool
	accounts      []string
	harden        bool
	gitName       string
	gitEmail      string
	defaultGithub bool
}

func (a *app) cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	o := setupOptions{}
	var rolesArg, accountsArg string
	var protected, unprotected bool
	fs.StringVar(&o.persona, "persona", "", "persona name")
	fs.StringVar(&rolesArg, "roles", "", "comma separated: github,client,server,dotfiles")
	fs.BoolVar(&protected, "protected", false, "protect keys on disk with the passphrase (default)")
	fs.BoolVar(&unprotected, "unprotected", false, "write keys without passphrase")
	fs.StringVar(&accountsArg, "accounts", "", "server role: accounts to authorize, comma separated")
	fs.BoolVar(&o.harden, "harden", false, "server role: disable password login after a proven key login")
	fs.StringVar(&o.gitName, "git-name", "", "git user.name to set")
	fs.StringVar(&o.gitEmail, "git-email", "", "git user.email to set")
	fs.BoolVar(&o.defaultGithub, "default-github", false, "make this persona own plain github.com")
	if err := fs.Parse(args); err != nil {
		return nil
	}
	if o.persona == "" || rolesArg == "" {
		return errors.New("setup needs --persona and --roles")
	}
	o.roles = strings.Split(rolesArg, ",")
	for _, r := range o.roles {
		if !contains(roles.All, r) {
			return fmt.Errorf("unknown role %q", r)
		}
	}
	o.protected = !unprotected
	if accountsArg != "" {
		o.accounts = strings.Split(accountsArg, ",")
	} else {
		o.accounts = []string{a.plat.User}
	}
	return a.setup(o)
}

func (a *app) setupInteractive() error {
	names, err := a.vault.List()
	if err != nil {
		return err
	}
	ui.Section("Set up this machine  (1/3)  Persona")
	var opts []ui.Option
	for _, n := range names {
		p, err := a.vault.Load(n)
		hint := ""
		if err == nil {
			hint = "github " + short(p.Env["github_fingerprint"]) + "  admin " + short(p.Env["admin_fingerprint"]) + "  created " + day(p.Env["created"])
		}
		opts = append(opts, ui.Option{Key: n, Label: n, Hint: hint})
	}
	opts = append(opts, ui.Option{Key: "+new", Label: "+ create a new persona"})
	choice, err := ui.Select("Persona", opts)
	if err != nil {
		return err
	}
	if choice == "+new" {
		u, err := a.personaNewInteractive()
		if err != nil {
			return err
		}
		choice = u.Name
	}

	ui.Section(fmt.Sprintf("Set up this machine  (2/3)  Roles for persona %q", choice))
	pre := a.state.Personas[choice]
	if len(pre) == 0 {
		pre = []string{roles.Github}
	}
	chosen, err := ui.MultiSelect("Roles", []ui.Option{
		{Key: roles.Github, Label: "github", Hint: "pull and push repos with the GitHub key"},
		{Key: roles.Client, Label: "client", Hint: "ssh into your machines with the admin key"},
		{Key: roles.Server, Label: "server", Hint: "let the admin key log in to this machine"},
		{Key: roles.Dotfiles, Label: "dotfiles", Hint: "clone and install your dotfiles (needs github)"},
	}, pre)
	if err != nil {
		return err
	}
	if len(chosen) == 0 {
		return errors.New("no roles chosen")
	}
	if contains(chosen, roles.Dotfiles) && !contains(chosen, roles.Github) && !a.state.HasRole(roles.Github) {
		ui.Report("warn", "dotfiles without github: the clone will be read-only over https")
	}

	ui.Section("Set up this machine  (3/3)  Options")
	o := setupOptions{persona: choice, roles: chosen, protected: true, accounts: []string{a.plat.User}}
	if contains(chosen, roles.Github) || contains(chosen, roles.Client) {
		def := "protected"
		hint := ""
		if a.plat.Headless && a.plat.AgentSock == "" {
			def = "unprotected"
			hint = "this machine looks headless and has no agent, so unprotected is preselected"
		}
		if hint != "" {
			ui.Report("info", "%s", hint)
		}
		mode, err := ui.Select("Private key on disk", orderFirst(def, []ui.Option{
			{Key: "protected", Label: "protected", Hint: "encrypted with the passphrase, remembered by ssh-agent or keychain"},
			{Key: "unprotected", Label: "unprotected", Hint: "plain file, for scripts and cron on headless machines"},
		}))
		if err != nil {
			return err
		}
		o.protected = mode == "protected"
	}
	if contains(chosen, roles.Server) {
		accOpts := []ui.Option{{Key: a.plat.User, Label: a.plat.User, Hint: "current user"}}
		pre := []string{a.plat.User}
		if a.plat.User != "root" && a.plat.IsRoot {
			accOpts = append(accOpts, ui.Option{Key: "root", Label: "root"})
		}
		if a.plat.IsRoot {
			for _, h := range homeUsers() {
				if h != a.plat.User {
					accOpts = append(accOpts, ui.Option{Key: h, Label: h})
				}
			}
		}
		o.accounts, err = ui.MultiSelect("Accounts that accept the admin key", accOpts, pre)
		if err != nil {
			return err
		}
		eff := a.ctx.ReportSSHD()
		hardenHint := "write a drop-in that wins over cloud-init, after a proven key login"
		if eff != nil && eff.PasswordAuthentication != "yes" {
			hardenHint = "already off"
		}
		o.harden = ui.Confirm("Disable password login? ("+hardenHint+")", false)
	}
	if contains(chosen, roles.Github) {
		n, e := roles.CurrentGitIdentity()
		if ui.Confirm(fmt.Sprintf("Set git identity? (currently %q <%s>)", n, e), n == "" || e == "") {
			o.gitName, _ = ui.Input("git user.name", n, nil)
			o.gitEmail, _ = ui.Input("git user.email", e, nil)
		}
		if a.state.Default != "" && a.state.Default != choice {
			o.defaultGithub = ui.Confirm(fmt.Sprintf("Make %q the persona for plain github.com instead of %q?", choice, a.state.Default), false)
		}
	}
	return a.setup(o)
}

// setup applies the answers.
func (a *app) setup(o setupOptions) error {
	p, err := a.vault.Load(o.persona)
	if err != nil {
		return err
	}
	needsKeys := contains(o.roles, roles.Github) || contains(o.roles, roles.Client)
	var u *persona.Unlocked
	var pass []byte
	if needsKeys {
		ui.Section(fmt.Sprintf("Unlock persona %q", o.persona))
		u, pass, err = a.unlock(p)
		if err != nil {
			return err
		}
		ui.Report("ok", "bundle decrypted; github %s and admin %s match the public keys", u.Github.Fingerprint, u.Admin.Fingerprint)
	}

	ui.Section(fmt.Sprintf("Applying  persona %q  roles %s", o.persona, strings.Join(o.roles, ", ")))
	if o.defaultGithub {
		a.state.Default = o.persona
	}
	if needsKeys {
		if err := a.ctx.InstallKeys(u, o.roles, o.protected, pass); err != nil {
			return err
		}
		if contains(o.roles, roles.Github) {
			if _, err := a.ctx.VerifyGithub(u); err != nil {
				ui.Report("warn", "GitHub verification skipped; rerun setup once the key is registered")
			}
			if err := a.ctx.GitIdentity(o.gitName, o.gitEmail); err != nil {
				ui.Report("warn", "%v", err)
			}
		}
	}
	if contains(o.roles, roles.Server) {
		if err := a.ctx.InstallAuthorizedKey(o.persona, p.AdminPub, o.accounts); err != nil {
			return err
		}
		if err := a.ctx.EnsureSSHD(); err != nil {
			ui.Report("warn", "%v", err)
		}
		if o.harden {
			if err := a.ctx.Harden(p.Env["admin_fingerprint"], o.accounts); err != nil {
				ui.Report("warn", "hardening not applied: %v", err)
			}
		} else {
			ui.Report("--", "password login left unchanged (not requested)")
		}
	}
	if err := a.save(); err != nil {
		return err
	}
	ui.Report("ok", "state written to %s", a.paths.State)

	if findings := a.scanLegacy(); len(findings) > 0 {
		ui.Section("Old material found on this machine")
		if a.yes {
			ui.Report("info", "%d finding(s); run dfm cleanup to review them", len(findings))
		} else if err := a.cleanupInteractive(findings, p.Env["admin_fingerprint"]); err != nil {
			ui.Report("warn", "%v", err)
		}
	}
	if contains(o.roles, roles.Dotfiles) {
		ui.Section("Dotfiles")
		if err := a.ctx.Dotfiles(); err != nil {
			ui.Report("warn", "%v", err)
		}
	}
	ui.Section("Done")
	fmt.Println(" " + a.state.Summary())
	return nil
}

// unlock asks for the passphrase until the bundle opens or the user gives up.
func (a *app) unlock(p *vault.Persona) (*persona.Unlocked, []byte, error) {
	for attempt := 1; attempt <= 3; attempt++ {
		pass, err := ui.Passphrase("Passphrase for persona " + p.Name)
		if err != nil {
			return nil, nil, err
		}
		u, err := persona.Unlock(p, pass)
		if err == nil {
			return u, pass, nil
		}
		ui.Report("fail", "%v", err)
		if a.yes {
			return nil, nil, err
		}
	}
	return nil, nil, errors.New("too many failed attempts")
}

func (a *app) scanLegacy() []cleanup.Finding {
	personas, _ := a.vault.LoadAll()
	return cleanup.Scan(a.plat, a.paths, a.vault, personas)
}

func (a *app) cmdCleanup(args ...string) error {
	removeAll := len(args) > 0 && args[0] == "--remove"
	findings := a.scanLegacy()
	ui.Section("Old material on this machine")
	if len(findings) == 0 {
		ui.Report("ok", "nothing to clean up")
		return nil
	}
	keep := ""
	if a.state.Default != "" {
		if p, err := a.vault.Load(a.state.Default); err == nil {
			keep = p.Env["admin_fingerprint"]
		}
	}
	if removeAll {
		if a.plat.IsSSH {
			ui.Report("warn", "you are connected over SSH: removals affect new sessions, keep this one open until a new login works")
		}
		for _, f := range findings {
			res, err := cleanup.Remove(f, a.paths.BackupDir, keep)
			if err != nil {
				ui.Report("fail", "%s: %v", f.Path, err)
				continue
			}
			ui.Report("ok", "%s: %s", f.Path, res)
		}
		return nil
	}
	if a.yes {
		for _, f := range findings {
			ui.Report("info", "%s", f)
		}
		return errors.New("cleanup needs confirmation; run without --yes, or pass --remove to remove everything listed (with backups)")
	}
	return a.cleanupInteractive(findings, keep)
}

func (a *app) cleanupInteractive(findings []cleanup.Finding, keep string) error {
	var opts []ui.Option
	var pre []string
	for i, f := range findings {
		k := fmt.Sprint(i)
		opts = append(opts, ui.Option{Key: k, Label: f.Path, Hint: f.Detail})
		pre = append(pre, k)
	}
	ui.Report("info", "removed files go to %s first; at least one key stays in every authorized_keys", a.paths.BackupDir)
	if a.plat.IsSSH {
		ui.Report("warn", "you are connected over SSH: removals affect new sessions, keep this one open until a new login works")
	}
	chosen, err := ui.MultiSelect("Remove", opts, pre)
	if err != nil {
		return err
	}
	for _, k := range chosen {
		var idx int
		fmt.Sscan(k, &idx)
		f := findings[idx]
		res, err := cleanup.Remove(f, a.paths.BackupDir, keep)
		if err != nil {
			ui.Report("fail", "%s: %v", f.Path, err)
			continue
		}
		ui.Report("ok", "%s: %s", f.Path, res)
	}
	return nil
}

func (a *app) cmdDoctor() error {
	ui.Section("Doctor  " + a.plat.Hostname)
	personas, _ := a.vault.LoadAll()
	warnings := 0
	for _, r := range doctor.Run(a.plat, a.paths, a.state, a.vault, personas) {
		ui.Report(string(r.Level), "%s", r.Text)
		if r.Level == doctor.Warn {
			warnings++
		}
	}
	fmt.Printf("\n %d warning(s).\n", warnings)
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func short(fp string) string {
	if len(fp) > 15 {
		return fp[:15] + "..."
	}
	return fp
}

func day(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ts
}

func orderFirst(key string, opts []ui.Option) []ui.Option {
	for i, o := range opts {
		if o.Key == key && i > 0 {
			return append([]ui.Option{o}, append(opts[:i:i], opts[i+1:]...)...)
		}
	}
	return opts
}

func homeUsers() []string {
	var out []string
	entries, _ := os.ReadDir("/home")
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}
