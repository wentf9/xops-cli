package sftpshell

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/charmbracelet/x/term"
	"github.com/wentf9/xops-cli/internal/terminal"
)

type terminalFile interface {
	io.ReadWriteCloser
	Fd() uintptr
}

// editorInput owns a cancellable duplicate, while Fd identifies the borrowed
// terminal whose mode the runner restores. Reading never closes process stdin.
type editorInput struct {
	owned         terminal.PromptInput
	fd            uintptr
	mu            sync.Mutex
	stopped       bool
	endErr        error
	readers       sync.WaitGroup
	interruptOnce sync.Once
	interruptErr  error
}

func newEditorInput(reader io.Reader) (*editorInput, error) {
	owned, err := duplicateEditorInput(reader)
	if err != nil {
		return nil, fmt.Errorf("open SFTP prompt input failed: %w", err)
	}
	fd := ^uintptr(0)
	if file, ok := reader.(interface{ Fd() uintptr }); ok {
		fd = file.Fd()
	}
	return &editorInput{owned: owned, fd: fd}, nil
}
func (i *editorInput) Fd() uintptr             { return i.fd }
func (*editorInput) Write([]byte) (int, error) { return 0, fmt.Errorf("prompt input is read only") }
func (i *editorInput) Read(buf []byte) (int, error) {
	i.mu.Lock()
	if i.stopped {
		i.mu.Unlock()
		return 0, io.EOF
	}
	if i.endErr != nil {
		err := i.endErr
		i.mu.Unlock()
		return 0, err
	}
	i.readers.Add(1)
	i.mu.Unlock()
	defer i.readers.Done()
	n, err := i.owned.Read(buf)
	i.mu.Lock()
	if i.stopped {
		// Closing a prompt-owned pipe/console may report a platform close error.
		// It is our cancellation, not a new source failure for the next prompt.
		err = io.EOF
	} else if err != nil {
		i.endErr = err
	}
	i.mu.Unlock()
	// Ultraviolet ignores n when err is non-nil. Deliver the bytes first and
	// return the saved terminal error on the next read.
	if n > 0 {
		return n, nil
	}
	return n, err
}
func (i *editorInput) Interrupt() {
	i.interruptOnce.Do(func() {
		i.mu.Lock()
		i.stopped = true
		i.mu.Unlock()
		i.interruptErr = i.owned.Interrupt()
	})
}
func (i *editorInput) EndError() error { i.mu.Lock(); defer i.mu.Unlock(); return i.endErr }

func (i *editorInput) Wait() { i.readers.Wait() }
func (i *editorInput) Close() error {
	i.Interrupt()
	i.Wait()
	if err := errors.Join(i.interruptErr, i.owned.Close()); err != nil {
		return fmt.Errorf("close SFTP prompt input failed: %w", err)
	}
	return nil
}

// Keep a separate snapshot because Bubble Tea's shutdown currently discards
// restoration errors. The owner restores and reports errors on every path.
func captureTerminalState(streams ...any) (func() error, error) {
	type saved struct {
		fd    uintptr
		state *term.State
	}
	var states []saved
	for _, stream := range streams {
		file, ok := stream.(interface{ Fd() uintptr })
		if !ok || !term.IsTerminal(file.Fd()) {
			continue
		}
		state, err := term.GetState(file.Fd())
		if err != nil {
			return nil, fmt.Errorf("capture terminal state failed: %w", err)
		}
		states = append(states, saved{file.Fd(), state})
	}
	return func() error {
		var result error
		for _, s := range states {
			if err := term.Restore(s.fd, s.state); err != nil {
				result = errors.Join(result, fmt.Errorf("restore terminal state failed: %w", err))
			}
		}
		return result
	}, nil
}

type editorOutput struct {
	writer io.Writer
	cancel func()
	mu     sync.Mutex
	err    error
}

func (o *editorOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n, err := o.writer.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil && o.err == nil {
		o.err = fmt.Errorf("write SFTP prompt failed: %w", err)
		if o.cancel != nil {
			o.cancel()
		}
	}
	return n, err
}
func (o *editorOutput) Err() error { o.mu.Lock(); defer o.mu.Unlock(); return o.err }

type editorFileOutput struct {
	*editorOutput
	file terminalFile
}

func (o *editorFileOutput) Fd() uintptr { return o.file.Fd() }
func (*editorFileOutput) Read([]byte) (int, error) {
	return 0, fmt.Errorf("prompt output is write only")
}
func (*editorFileOutput) Close() error { return nil } // Output is borrowed from Shell.
