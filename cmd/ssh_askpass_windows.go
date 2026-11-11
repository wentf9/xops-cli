//go:build windows

package cmd

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

const askpassHeaderReadLimit = 512

func realWindowsAskpassEnv() windowsAskpassEnv {
	return windowsAskpassEnv{
		getenv: os.Getenv,
		isRegularFile: func(p string) bool {
			info, err := os.Stat(p)
			return err == nil && !info.IsDir()
		},
		readHeader: readWindowsAskpassHeader,
		absPath: func(p string) string {
			if abs, err := filepath.Abs(p); err == nil {
				return abs
			}
			return p
		},
	}
}

func readWindowsAskpassHeader(targetPath string) ([]byte, error) {
	f, err := os.Open(targetPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var buf [askpassHeaderReadLimit]byte
	n, readErr := io.ReadFull(f, buf[:])
	if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
		return nil, readErr
	}
	return buf[:n], nil
}

func findSystemAskpass() string {
	return findWindowsSystemAskpass(realWindowsAskpassEnv())
}

func buildAskpassCommand(ctx context.Context, askpassProg, prompt string) (*exec.Cmd, error) {
	exe, args, err := planWindowsAskpassCommand(askpassProg, prompt, realWindowsAskpassEnv())
	if err != nil {
		return nil, err
	}
	return exec.CommandContext(ctx, exe, args...), nil
}
