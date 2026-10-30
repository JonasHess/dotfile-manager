// Package ui holds the terminal interaction: header, menus, forms, the
// passphrase prompt and the progress printer. Everything that the
// non-interactive mode must be able to answer goes through small
// functions so main can substitute flag values.
package ui

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

var (
	dim    = lipgloss.NewStyle().Faint(true)
	bold   = lipgloss.NewStyle().Bold(true)
	green  = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	yellow = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	red    = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
)

// Interactive reports whether stdin is a terminal.
func Interactive() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

// Header prints the one-line banner.
func Header(version, summary string) {
	fmt.Printf("\n %s %s\n\n", bold.Render("dfm "+version), dim.Render(summary))
}

// Report prints a progress line with a status tag.
func Report(status, format string, args ...any) {
	tag := fmt.Sprintf("[%s]", status)
	switch status {
	case "ok":
		tag = green.Render(tag)
	case "warn":
		tag = yellow.Render(tag)
	case "fail":
		tag = red.Render(tag)
	default:
		tag = dim.Render(tag)
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Printf(" %-6s %s\n", tag, strings.ReplaceAll(msg, "\n", "\n        "))
}

// Section prints a heading.
func Section(title string) { fmt.Printf("\n %s\n\n", bold.Render(title)) }

// Option is one menu entry with an optional hint.
type Option struct {
	Key, Label, Hint string
}

// Select shows a single-choice menu and returns the chosen key.
func Select(title string, opts []Option) (string, error) {
	var hopts []huh.Option[string]
	width := 0
	for _, o := range opts {
		if len(o.Label) > width {
			width = len(o.Label)
		}
	}
	for _, o := range opts {
		label := o.Label
		if o.Hint != "" {
			label = fmt.Sprintf("%-*s   %s", width, o.Label, dim.Render(o.Hint))
		}
		hopts = append(hopts, huh.NewOption(label, o.Key))
	}
	var choice string
	err := huh.NewSelect[string]().Title(title).Options(hopts...).Value(&choice).Run()
	return choice, err
}

// MultiSelect shows checkboxes and returns the chosen keys.
func MultiSelect(title string, opts []Option, preselected []string) ([]string, error) {
	var hopts []huh.Option[string]
	for _, o := range opts {
		label := o.Label
		if o.Hint != "" {
			label = fmt.Sprintf("%-10s %s", o.Label, dim.Render(o.Hint))
		}
		h := huh.NewOption(label, o.Key)
		for _, p := range preselected {
			if p == o.Key {
				h = h.Selected(true)
			}
		}
		hopts = append(hopts, h)
	}
	var chosen []string
	err := huh.NewMultiSelect[string]().
		Title(title).
		Description("space toggles an entry, enter confirms the ticked ones").
		Options(hopts...).
		Validate(func(v []string) error {
			if len(v) == 0 {
				return errors.New("tick at least one entry with space, then press enter")
			}
			return nil
		}).
		Value(&chosen).Run()
	return chosen, err
}

// Confirm asks a yes/no question.
func Confirm(prompt string, def bool) bool {
	v := def
	if err := huh.NewConfirm().Title(prompt).Affirmative("Yes").Negative("No").Value(&v).Run(); err != nil {
		return def
	}
	return v
}

// Input asks for one line of text with a prefilled value.
func Input(title, value string, validate func(string) error) (string, error) {
	in := huh.NewInput().Title(title).Value(&value)
	if validate != nil {
		in = in.Validate(validate)
	}
	err := in.Run()
	return strings.TrimSpace(value), err
}

// PassphraseFD, when non-negative, is a file descriptor passphrases are
// read from (one line each) instead of the terminal. It exists for scripted
// runs and tests; passphrases never travel in arguments or environment.
var PassphraseFD = -1

// Passphrase reads a secret from the terminal with echo off. It never goes
// through a form so it is not kept in any widget state.
func Passphrase(prompt string) ([]byte, error) {
	if PassphraseFD >= 0 {
		f := os.NewFile(uintptr(PassphraseFD), "passphrase-fd")
		line, err := bufio.NewReader(f).ReadString('\n')
		if err != nil && line == "" {
			return nil, fmt.Errorf("passphrase fd %d: %w", PassphraseFD, err)
		}
		return []byte(strings.TrimRight(line, "\r\n")), nil
	}
	fmt.Printf(" %s: ", prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, err
	}
	return b, nil
}

// WaitEnter blocks until the user presses enter. Returns false when the
// user typed "s" (skip) or input is closed.
func WaitEnter(msg string) bool {
	fmt.Printf(" %s ", dim.Render(msg))
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	return strings.TrimSpace(strings.ToLower(line)) != "s"
}

// Table prints aligned rows.
func Table(rows [][]string) {
	widths := map[int]int{}
	for _, r := range rows {
		for i, c := range r {
			if len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}
	for _, r := range rows {
		fmt.Print(" ")
		for i, c := range r {
			fmt.Printf("  %-*s", widths[i], c)
		}
		fmt.Println()
	}
}

// Dim and Bold expose the styles for ad hoc lines.
func Dim(s string) string  { return dim.Render(s) }
func Bold(s string) string { return bold.Render(s) }
