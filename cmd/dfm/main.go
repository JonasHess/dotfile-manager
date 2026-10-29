// dfm is the dotfile-manager command: a wizard that installs SSH keys from
// an encrypted vault, prepares machines as GitHub clients, SSH clients or
// SSH servers, and manages personas in the vault.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/JonasHess/dotfile-manager/internal/platform"
	"github.com/JonasHess/dotfile-manager/internal/roles"
	"github.com/JonasHess/dotfile-manager/internal/state"
	"github.com/JonasHess/dotfile-manager/internal/ui"
	"github.com/JonasHess/dotfile-manager/internal/vault"
)

var version = "dev"

// app carries everything the flows share.
type app struct {
	plat  platform.Info
	paths state.Paths
	state *state.State
	vault *vault.Vault
	yes   bool // non-interactive: take defaults, never prompt
	ctx   *roles.Context
}

func usage() {
	fmt.Fprint(os.Stderr, `dfm - SSH keys and machine setup from an encrypted vault

Usage:
  dfm [--vault URL|DIR] [--yes] [--passphrase-fd N]   interactive main menu
  dfm setup --persona NAME --roles github,client,server,dotfiles
            [--protected|--unprotected] [--accounts root,user] [--harden]
            [--git-name NAME --git-email MAIL] [--default-github]
  dfm persona list|new|verify|rotate|passphrase|publish [NAME]
  dfm cleanup [--remove]                         find (and remove, with backups) legacy keys
  dfm doctor                                     health and lock-out checks
  dfm guard [--staged] [FILE...]                 secret guard (pre-commit, CI)
  dfm vault init DIR [--owner USER] [--dotfiles-repo URL]   create a new vault
  dfm version

The vault is taken from --vault, $DFM_VAULT, the last used vault, or
~/.local/share/dfm/vault.
`)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, ui.Dim(" error: ")+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	global := flag.NewFlagSet("dfm", flag.ContinueOnError)
	global.Usage = usage
	vaultFlag := global.String("vault", os.Getenv("DFM_VAULT"), "vault git URL or directory")
	yes := global.Bool("yes", false, "non-interactive: accept defaults, fail instead of asking")
	showVersion := global.Bool("version", false, "print version")
	passFD := global.Int("passphrase-fd", -1, "read passphrases from this file descriptor instead of the terminal")
	if err := global.Parse(args); err != nil {
		return nil
	}
	if *showVersion {
		fmt.Println("dfm", version)
		return nil
	}
	ui.PassphraseFD = *passFD
	rest := global.Args()
	cmd := ""
	if len(rest) > 0 {
		cmd, rest = rest[0], rest[1:]
	}

	switch cmd {
	case "version":
		fmt.Println("dfm", version)
		return nil
	case "guard":
		return cmdGuard(rest)
	case "vault":
		return cmdVault(rest)
	case "help", "-h", "--help":
		usage()
		return nil
	}

	a, err := newApp(*vaultFlag, *yes)
	if err != nil {
		return err
	}
	switch cmd {
	case "":
		if !ui.Interactive() {
			usage()
			return errors.New("no terminal; use a subcommand with flags")
		}
		return a.menu()
	case "setup":
		return a.cmdSetup(rest)
	case "persona":
		return a.cmdPersona(rest)
	case "cleanup":
		return a.cmdCleanup(rest...)
	case "doctor":
		return a.cmdDoctor()
	default:
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func newApp(vaultArg string, yes bool) (*app, error) {
	a := &app{plat: platform.Detect(), yes: yes}
	a.paths = state.NewPaths(a.plat.Home)
	a.state = state.Load(a.paths.State)

	dir, source := resolveVault(vaultArg, a.state.Vault, vault.DefaultDir(a.plat.Home))
	v, note, err := vault.Ensure(dir, source)
	if err != nil {
		return nil, err
	}
	a.vault = v
	a.state.Vault = dir
	a.ctx = &roles.Context{
		Plat: a.plat, Paths: a.paths, State: a.state, Vault: v, Version: version,
		Report: ui.Report,
	}
	if !yes {
		a.ctx.Confirm = ui.Confirm
		a.ctx.WaitEnter = ui.WaitEnter
	}
	if note != "" {
		ui.Report("info", "%s (%s)", note, dir)
	}
	return a, nil
}

// resolveVault turns the --vault argument into a checkout directory and an
// optional clone source. A local directory is used in place; a URL is
// cloned into the default directory.
func resolveVault(arg, last, def string) (dir, source string) {
	switch {
	case arg == "":
		if last != "" {
			return last, ""
		}
		return def, ""
	case isURL(arg):
		return def, arg
	default:
		return arg, ""
	}
}

func isURL(s string) bool {
	return strings.Contains(s, "://") || strings.HasPrefix(s, "git@")
}

func (a *app) save() error { return a.state.Save(a.paths.State, version) }

// menu is the interactive main menu.
func (a *app) menu() error {
	for {
		ui.Header(version, a.plat.Summary())
		findings := a.scanLegacy()
		cleanupHint := "nothing to clean up"
		if len(findings) > 0 {
			cleanupHint = fmt.Sprintf("%d finding(s) on this machine", len(findings))
		}
		choice, err := ui.Select("What do you want to do?", []ui.Option{
			{Key: "setup", Label: "Set up this machine", Hint: "persona, roles, dotfiles"},
			{Key: "personas", Label: "Personas", Hint: "create, list, verify, rotate, passphrase"},
			{Key: "cleanup", Label: "Clean up old keys", Hint: cleanupHint},
			{Key: "doctor", Label: "Doctor", Hint: "agent, sshd, permissions, lock-out risks"},
			{Key: "quit", Label: "Quit"},
		})
		if err != nil {
			return nil
		}
		fmt.Println(" " + ui.Dim(a.state.Summary()))
		switch choice {
		case "setup":
			err = a.setupInteractive()
		case "personas":
			err = a.personasMenu()
		case "cleanup":
			err = a.cmdCleanup()
		case "doctor":
			err = a.cmdDoctor()
		case "quit":
			return nil
		}
		if err != nil {
			ui.Report("fail", "%v", err)
		}
		if !ui.WaitEnter("press enter to return to the menu") {
			return nil
		}
	}
}
