//go:build windows

package sftpshell

import (
	tea "charm.land/bubbletea/v2"
	"context"
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
func watchEditorSize(ctx context.Context, size editorTerminalSize, send func(tea.Msg)) func() {
	if size.file == nil {
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !size.update(send) {
					return
				}
			}
		}
	}()
	return func() { cancel(); <-done }
}

func makeEditorRaw(fd uintptr) error { _, err := term.MakeRaw(fd); return err }
