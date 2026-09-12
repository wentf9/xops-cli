package sftpshell

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/wentf9/xops-cli/internal/terminal"
)

// Batch input does not instantiate readline or own a terminal. Interrupting
// the duplicated input wakes Scanner on cancellation without closing stdin.
func batchCommandReader(ctx context.Context, input io.Reader) (func() (string, error), func() error, error) {
	owned, err := terminal.DuplicatePromptInput(input)
	if err != nil {
		return nil, nil, fmt.Errorf("open batch command input: %w", err)
	}
	scanner := bufio.NewScanner(owned)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	done := make(chan error, 1)
	stop := context.AfterFunc(ctx, func() { done <- owned.Interrupt() })
	closeInput := func() error {
		var interruptErr error
		if !stop() {
			interruptErr = <-done
		}
		return errors.Join(interruptErr, owned.Close())
	}
	read := func() (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if scanner.Scan() {
			return scanner.Text(), nil
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("read batch command: %w", err)
		}
		return "", io.EOF
	}
	return read, closeInput, nil
}
