//go:build windows

package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/wentf9/xops-cli/internal/terminal"
)

// copyStdinTo owns a duplicate input handle. Console reads wait on input and a
// cancellation event, never on ReadFile after a possibly non-character event.
// The caller cancels and waits for done before another reader takes the console.
func copyStdinTo(src *os.File, dst io.Writer) (cancel func() error, done <-chan error, err error) {
	if src == nil {
		return nil, nil, fmt.Errorf("interactive stdin is nil")
	}
	input, err := terminal.DuplicateInteractiveInput(src)
	if err != nil {
		return nil, nil, fmt.Errorf("duplicate interactive stdin failed: %w", err)
	}
	ctx, stop := context.WithCancel(context.Background())
	var once sync.Once
	var cancelErr error
	cancelCopy := func() error {
		once.Do(func() {
			stop()
			cancelErr = input.Interrupt()
		})
		return cancelErr
	}
	doneCh := make(chan error, 1)
	go func() {
		var copyErr error
		defer func() {
			copyErr = errors.Join(copyErr, input.Close())
			doneCh <- copyErr
			close(doneCh)
		}()
		buf := make([]byte, 1024)
		for {
			n, readErr := input.Read(buf)
			if ctx.Err() != nil {
				return
			}
			if n > 0 {
				written, writeErr := dst.Write(buf[:n])
				if writeErr == nil && written != n {
					writeErr = io.ErrShortWrite
				}
				if writeErr != nil {
					if ctx.Err() == nil {
						copyErr = fmt.Errorf("copy stdin to SSH session failed: %w", writeErr)
					}
					return
				}
			}
			if readErr != nil {
				if !errors.Is(readErr, io.EOF) {
					copyErr = fmt.Errorf("read stdin failed: %w", readErr)
				}
				return
			}
		}
	}()
	return cancelCopy, doneCh, nil
}
