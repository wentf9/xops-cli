package sftpshell

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// Session state outlives individual prompt programs and terminal handoffs.
// It owns no terminal resources or goroutines between prompts.
type editorSession struct {
	history *commandHistory
	prompt  sync.Mutex
	decoder editorDecoder
}

func (s *Shell) getEditorSession(historyFile string, stderr io.Writer) (*editorSession, error) {
	s.editorStateMu.Lock()
	defer s.editorStateMu.Unlock()
	if s.editorState != nil {
		return s.editorState, nil
	}
	history, err := newCommandHistory(historyFile)
	if err != nil {
		// Read an optional snapshot without creating a writable sidecar. A failed
		// snapshot still permits an empty, usable in-memory history.
		var lines []string
		info, readErr := os.Stat(historyFile)
		if readErr == nil && info.Mode().IsRegular() {
			lines, readErr = readCommandHistory(historyFile)
		}
		history = &commandHistory{lines: lines}
		warning := errors.Join(err, readErr)
		if stderr != nil {
			if _, writeErr := fmt.Fprintf(stderr, "SFTP history persistence unavailable; using session history: %v\n", warning); writeErr != nil {
				return nil, fmt.Errorf("report unavailable SFTP history failed: %w", writeErr)
			}
		}
	}
	s.editorState = &editorSession{history: history}
	return s.editorState, nil
}
