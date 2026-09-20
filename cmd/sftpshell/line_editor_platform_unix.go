//go:build !windows

package sftpshell

import (
	tea "charm.land/bubbletea/v2"
	"context"
	"github.com/charmbracelet/x/term"
	"github.com/charmbracelet/x/termios"
	"github.com/wentf9/xops-cli/internal/terminal"
	"io"
)

func duplicateEditorInput(input io.Reader) (terminal.PromptInput, error) {
	return terminal.DuplicatePromptInput(input)
}

// Bubble Tea receives SIGWINCH directly on Unix.
func watchEditorSize(context.Context, io.Writer, func(tea.Msg)) func() { return func() {} }

// With an externally managed input stream Bubble Tea renders for cooked
// output. Keep newline processing enabled while disabling input echo/editing.
func makeEditorRaw(fd uintptr) error {
	if _, err := term.MakeRaw(fd); err != nil {
		return err
	}
	state, err := termios.GetTermios(int(fd))
	if err != nil {
		return err
	}
	// Darwin uses uint64 speeds; Linux uses uint32.
	//nolint:unconvert
	return termios.SetTermios(int(fd), uint32(state.Ispeed), uint32(state.Ospeed), nil, nil,
		map[termios.O]bool{termios.OPOST: true, termios.ONLCR: true}, nil, nil)
}
