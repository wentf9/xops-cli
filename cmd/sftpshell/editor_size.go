package sftpshell

import (
	"fmt"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/term"
)

// Use one terminal for both the initial renderer size and subsequent changes.
// Prefer stdout, then stdin for redirected output, then a fixed usable default.
type editorTerminalSize struct {
	file          interface{ Fd() uintptr }
	width, height int
}

func selectEditorTerminal(streams ...any) editorTerminalSize {
	for _, stream := range streams {
		if file, ok := stream.(interface{ Fd() uintptr }); ok && term.IsTerminal(file.Fd()) {
			width, height, err := term.GetSize(file.Fd())
			if err == nil && width > 0 && height > 0 {
				return editorTerminalSize{file: file, width: width, height: height}
			}
		}
	}
	return editorTerminalSize{width: 80, height: 24}
}

// The prompt's size watcher owns this copy of the last dimensions. Ignore
// transient zero dimensions rather than clearing the renderer during a resize.
func (s *editorTerminalSize) update(send func(tea.Msg)) bool {
	width, height, err := term.GetSize(s.file.Fd())
	if err != nil {
		send(editorInputEnded{err: fmt.Errorf("read terminal size failed: %w", err)})
		return false
	}
	if width > 0 && height > 0 && (width != s.width || height != s.height) {
		s.width, s.height = width, height
		send(tea.WindowSizeMsg{Width: width, Height: height})
	}
	return true
}
