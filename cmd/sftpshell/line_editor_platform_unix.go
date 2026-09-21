//go:build !windows

package sftpshell

import (
	tea "charm.land/bubbletea/v2"
	"context"
	"github.com/charmbracelet/x/term"
	"github.com/charmbracelet/x/termios"
	"github.com/wentf9/xops-cli/internal/terminal"
	"io"
	"os"
	"os/signal"
	"syscall"
)

func duplicateEditorInput(input io.Reader) (terminal.PromptInput, error) {
	return terminal.DuplicatePromptInput(input)
}

// Watch the selected terminal even when Bubble Tea has no terminal output.
func watchEditorSize(ctx context.Context, size editorTerminalSize, send func(tea.Msg)) func() {
	if size.file == nil {
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	changed := make(chan os.Signal, 1)
	signal.Notify(changed, syscall.SIGWINCH)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer signal.Stop(changed)
		for {
			select {
			case <-ctx.Done():
				return
			case <-changed:
				if !size.update(send) {
					return
				}
			}
		}
	}()
	return func() { cancel(); <-done }
}

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
