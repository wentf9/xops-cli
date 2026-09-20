//go:build windows

package sftpshell

import (
	tea "charm.land/bubbletea/v2"
	"context"
	"fmt"
	"github.com/charmbracelet/x/term"
	"github.com/wentf9/xops-cli/internal/terminal"
	"io"
	"os"
	"time"
)

func duplicateEditorInput(input io.Reader) (terminal.PromptInput, error) {
	if file, ok := input.(*os.File); ok {
		return terminal.DuplicateInteractiveInput(file)
	}
	return terminal.DuplicatePromptInput(input)
}

// Windows has no SIGWINCH. Poll only while a prompt owns the console; the
// native input reader remains dedicated to keyboard events and cancellation.
func watchEditorSize(ctx context.Context, output io.Writer, send func(tea.Msg)) func() {
	file, ok := output.(interface{ Fd() uintptr })
	if !ok || !term.IsTerminal(file.Fd()) {
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		width, height := 0, 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				w, h, err := term.GetSize(file.Fd())
				if err != nil {
					send(editorInputEnded{err: fmt.Errorf("read terminal size failed: %w", err)})
					return
				}
				if w != width || h != height {
					width, height = w, h
					send(tea.WindowSizeMsg{Width: w, Height: h})
				}
			}
		}
	}()
	return func() { cancel(); <-done }
}

func makeEditorRaw(fd uintptr) error { _, err := term.MakeRaw(fd); return err }
