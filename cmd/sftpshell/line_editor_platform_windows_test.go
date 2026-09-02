//go:build windows

package sftpshell

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chzyer/readline"
	"golang.org/x/sys/windows"
)

func TestWindowsLineEditorDoesNotReadBeforePrompt(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create input pipe failed: %v", err)
	}
	defer closeTestResource(t, reader)
	defer closeTestResource(t, writer)

	shell := &Shell{cwd: "/", localCwd: t.TempDir()}
	editor, err := newLineEditor(context.Background(), reader, &bytes.Buffer{}, &bytes.Buffer{}, "", shell)
	if err != nil {
		t.Fatalf("create line editor failed: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := editor.Close(); closeErr != nil {
			t.Errorf("close line editor failed: %v", closeErr)
		}
	})

	time.Sleep(25 * time.Millisecond)
	if editor.instance.Terminal.IsReading() {
		t.Fatal("line editor started reading before Prompt entered raw mode")
	}
}

func TestWindowsConsoleModeRoundTrip(t *testing.T) {
	const originalMode = windows.ENABLE_ECHO_INPUT |
		windows.ENABLE_LINE_INPUT |
		windows.ENABLE_PROCESSED_INPUT |
		windows.ENABLE_WINDOW_INPUT
	setModes := []uint32{}
	platform := newTestWindowsPlatform(
		func(_ windows.Handle, mode *uint32) error {
			*mode = originalMode
			return nil
		},
		func(_ windows.Handle, mode uint32) error {
			setModes = append(setModes, mode)
			return nil
		},
	)

	if err := platform.preparePrompt(); err != nil {
		t.Fatalf("enter raw mode failed: %v", err)
	}
	if err := platform.exitRawMode(); err != nil {
		t.Fatalf("exit raw mode failed: %v", err)
	}
	if err := platform.exitRawMode(); err != nil {
		t.Fatalf("second exit raw mode failed: %v", err)
	}
	if err := platform.finishPrompt(nil); err != nil {
		t.Fatalf("finish prompt failed: %v", err)
	}

	wantRaw := uint32(windows.ENABLE_WINDOW_INPUT)
	if len(setModes) != 2 {
		t.Fatalf("SetConsoleMode call count = %d, want 2", len(setModes))
	}
	if setModes[0] != wantRaw {
		t.Errorf("raw console mode = %#x, want %#x", setModes[0], wantRaw)
	}
	if setModes[1] != originalMode {
		t.Errorf("restored console mode = %#x, want %#x", setModes[1], originalMode)
	}
}

func TestWindowsConsoleModeRestoreFailureIsReportedAndRetried(t *testing.T) {
	restoreErr := windows.ERROR_ACCESS_DENIED
	setCalls := 0
	platform := newTestWindowsPlatform(
		func(_ windows.Handle, mode *uint32) error {
			*mode = windows.ENABLE_ECHO_INPUT | windows.ENABLE_LINE_INPUT
			return nil
		},
		func(_ windows.Handle, _ uint32) error {
			setCalls++
			if setCalls == 2 {
				return restoreErr
			}
			return nil
		},
	)

	if err := platform.preparePrompt(); err != nil {
		t.Fatalf("enter raw mode failed: %v", err)
	}
	if err := platform.exitRawMode(); !errors.Is(err, restoreErr) {
		t.Fatalf("exit raw mode error = %v, want %v", err, restoreErr)
	}
	promptErr := platform.finishPrompt(readline.ErrInterrupt)
	if !errors.Is(promptErr, readline.ErrInterrupt) || !errors.Is(promptErr, restoreErr) {
		t.Fatalf("finish prompt error = %v, want interrupt and restore errors", promptErr)
	}
	if strings.Contains(promptErr.Error(), "\n") {
		t.Fatalf("finish prompt error contains a newline: %q", promptErr)
	}
	if err := platform.exitRawMode(); err != nil {
		t.Fatalf("retry exit raw mode failed: %v", err)
	}
	if setCalls != 3 {
		t.Fatalf("SetConsoleMode call count = %d, want 3", setCalls)
	}
}

func TestWindowsConsoleModePrepareFailureIsReported(t *testing.T) {
	getErr := windows.ERROR_INVALID_HANDLE
	platform := newTestWindowsPlatform(
		func(windows.Handle, *uint32) error {
			return getErr
		},
		func(windows.Handle, uint32) error {
			t.Fatal("SetConsoleMode called after GetConsoleMode failed")
			return nil
		},
	)

	err := platform.preparePrompt()
	if !errors.Is(err, getErr) {
		t.Fatalf("prepare prompt error = %v, want %v", err, getErr)
	}
	if !strings.Contains(err.Error(), "get Windows console mode failed") {
		t.Fatalf("prepare prompt error lacks context: %v", err)
	}
	if strings.Contains(err.Error(), "\n") {
		t.Fatalf("prepare prompt error contains a newline: %q", err)
	}
}

func newTestWindowsPlatform(getMode consoleModeGetter, setMode consoleModeSetter) *lineEditorPlatform {
	return &lineEditorPlatform{
		consoleMode: &windowsConsoleMode{
			handle:  windows.Handle(1),
			getMode: getMode,
			setMode: setMode,
		},
	}
}
