//go:build windows

package sftpshell

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/chzyer/readline"
	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

type consoleModeGetter func(windows.Handle, *uint32) error
type consoleModeSetter func(windows.Handle, uint32) error

type windowsConsoleMode struct {
	mu           sync.Mutex
	handle       windows.Handle
	getMode      consoleModeGetter
	setMode      consoleModeSetter
	originalMode uint32
	raw          bool
	promptErr    error
}

type lineEditorPlatform struct {
	consoleMode *windowsConsoleMode
}

func newLineEditorPlatform(input io.Reader) *lineEditorPlatform {
	file, ok := input.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return &lineEditorPlatform{}
	}
	return &lineEditorPlatform{
		consoleMode: &windowsConsoleMode{
			handle:  windows.Handle(file.Fd()),
			getMode: windows.GetConsoleMode,
			setMode: windows.SetConsoleMode,
		},
	}
}

func (p *lineEditorPlatform) configure(config *readline.Config) {
	config.FuncMakeRaw = p.enterRawMode
	config.FuncExitRaw = p.exitRawMode
}

func (*lineEditorPlatform) start(context.Context, *readline.Instance) {}

func (p *lineEditorPlatform) preparePrompt() error {
	if p.consoleMode == nil {
		return nil
	}
	p.consoleMode.mu.Lock()
	p.consoleMode.promptErr = nil
	p.consoleMode.mu.Unlock()
	return p.enterRawMode()
}

func (p *lineEditorPlatform) enterRawMode() error {
	if p.consoleMode == nil {
		return nil
	}
	mode := p.consoleMode
	mode.mu.Lock()
	defer mode.mu.Unlock()
	if mode.raw {
		return nil
	}
	var current uint32
	if err := mode.getMode(mode.handle, &current); err != nil {
		return mode.recordError("get Windows console mode failed", err)
	}
	raw := current &^ (windows.ENABLE_ECHO_INPUT | windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT)
	if err := mode.setMode(mode.handle, raw); err != nil {
		return mode.recordError("enable Windows console raw mode failed", err)
	}
	mode.originalMode = current
	mode.raw = true
	return nil
}

func (p *lineEditorPlatform) exitRawMode() error {
	if p.consoleMode == nil {
		return nil
	}
	mode := p.consoleMode
	mode.mu.Lock()
	defer mode.mu.Unlock()
	if !mode.raw {
		return nil
	}
	if err := mode.setMode(mode.handle, mode.originalMode); err != nil {
		return mode.recordError("restore Windows console mode failed", err)
	}
	mode.raw = false
	return nil
}

func (m *windowsConsoleMode) recordError(action string, err error) error {
	wrapped := fmt.Errorf("%s: %w", action, err)
	if m.promptErr == nil {
		m.promptErr = wrapped
		return wrapped
	}
	m.promptErr = fmt.Errorf("%w; %w", m.promptErr, wrapped)
	return wrapped
}

func (p *lineEditorPlatform) finishPrompt(promptErr error) error {
	if p.consoleMode == nil {
		return promptErr
	}
	p.consoleMode.mu.Lock()
	modeErr := p.consoleMode.promptErr
	p.consoleMode.promptErr = nil
	p.consoleMode.mu.Unlock()
	switch {
	case promptErr != nil && modeErr != nil:
		return fmt.Errorf("%w; %w", promptErr, modeErr)
	case promptErr != nil:
		return promptErr
	default:
		return modeErr
	}
}

func (*lineEditorPlatform) waitBeforeClose() {}

// prepareInstanceClose starts readline's terminal reader only when no Prompt
// ever did. The prompt input is already interrupted at this point, so the read
// cannot consume cooked console input, but it does let readline register its
// internal WaitGroup before Instance.Close waits on it.
func (*lineEditorPlatform) prepareInstanceClose(instance *readline.Instance, readStarted bool) {
	if readStarted {
		return
	}
	instance.Terminal.KickRead()
	for !instance.Terminal.IsReading() {
		time.Sleep(time.Millisecond)
	}
}
