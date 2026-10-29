package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/JonasHess/dotfile-manager/internal/guard"
)

// cmdGuard runs the secret guard over files given on the command line, the
// staged files of the current git repository (--staged), or the whole tree.
func cmdGuard(args []string) error {
	fs := flag.NewFlagSet("guard", flag.ContinueOnError)
	staged := fs.Bool("staged", false, "check the files staged in git")
	if err := fs.Parse(args); err != nil {
		return nil
	}
	files := map[string][]byte{}
	switch {
	case *staged:
		out, err := exec.Command("git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").Output()
		if err != nil {
			return fmt.Errorf("git diff --cached: %w", err)
		}
		for _, p := range strings.Split(string(out), "\x00") {
			if p == "" {
				continue
			}
			b, err := exec.Command("git", "show", ":"+p).Output()
			if err != nil {
				return err
			}
			files[p] = b
		}
	case fs.NArg() > 0:
		for _, p := range fs.Args() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			files[p] = b
		}
	default:
		out, err := exec.Command("git", "ls-files", "-z").Output()
		if err != nil {
			return fmt.Errorf("git ls-files: %w", err)
		}
		for _, p := range strings.Split(string(out), "\x00") {
			if p == "" {
				continue
			}
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			files[p] = b
		}
	}
	findings := guard.CheckAll(files)
	fmt.Print(guard.Summary(findings))
	if len(findings) > 0 {
		return errors.New("refusing: private material or malformed persona files")
	}
	return nil
}
