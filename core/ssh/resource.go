package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	logger "github.com/wentf9/xops-cli/core/log"
)

func closeResource(closer io.Closer, resource string) error {
	if closer == nil {
		return nil
	}
	if err := closer.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		return fmt.Errorf("close %s failed: %w", resource, err)
	}
	return nil
}

func joinResourceCloseError(target *error, closer io.Closer, resource string) {
	*target = errors.Join(*target, closeResource(closer, resource))
}

func debugCloseResource(l logger.DebugLogger, closer io.Closer, resource string) {
	if err := closeResource(closer, resource); err != nil {
		if l == nil {
			l = logger.NopLogger
		}
		l.Debugf("%v", err)
	}
}

func copySessionOutput(stdout, stderr io.Reader, stdoutWriter, stderrWriter io.Writer) func() error {
	return startSessionOutput(stdout, stderr, stdoutWriter, stderrWriter).wait
}

type sessionOutputCopy struct {
	failed <-chan error
	wait   func() error
}

// Report the first pump failure immediately, independently of the other stream
// reaching EOF. The owner closes the SSH session/transport and cancels capable
// writers before joining both workers through wait.
func startSessionOutput(stdout, stderr io.Reader, stdoutWriter, stderrWriter io.Writer) sessionOutputCopy {
	if stdoutWriter == nil {
		stdoutWriter = io.Discard
	}
	if stderrWriter == nil {
		stderrWriter = io.Discard
	}
	errCh := make(chan error, 2)
	failed := make(chan error, 1)
	var wg sync.WaitGroup
	var outputMu sync.Mutex

	copyOne := func(name string, dst io.Writer, src io.Reader) {
		wg.Go(func() {
			if src == nil {
				errCh <- nil
				return
			}
			_, err := io.Copy(serializedSessionOutput{mu: &outputMu, target: dst}, src)
			if err != nil {
				err = fmt.Errorf("copy SSH %s failed: %w", name, err)
				select {
				case failed <- err:
				default:
				}
			}
			errCh <- err
		})
	}
	copyOne("stdout", stdoutWriter, stdout)
	copyOne("stderr", stderrWriter, stderr)

	return sessionOutputCopy{failed: failed, wait: sync.OnceValue(func() error {
		wg.Wait()
		return errors.Join(<-errCh, <-errCh)
	})}
}

func waitSessionOutput(ctx context.Context, wait func() error, cancelOutput ...context.CancelFunc) error {
	done := make(chan error, 1)
	go func() { done <- wait() }()
	timer := time.NewTimer(sessionShutdownTimeout)
	defer timer.Stop()
	cancel := func() {
		for _, fn := range cancelOutput {
			if fn != nil {
				fn()
			}
		}
	}
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		cancel()
		return errors.Join(ctx.Err(), <-done)
	case <-timer.C:
		cancel()
		return errors.Join(fmt.Errorf("drain SSH output: %w", context.DeadlineExceeded), <-done)
	}
}

// Serialize writes, not reads: holding a lock for an entire io.Copy can deadlock
// when the remote command fills the other SSH stream before closing this one.
// Hiding ReaderFrom also prevents an underlying buffer from bypassing the lock.
type serializedSessionOutput struct {
	mu     *sync.Mutex
	target io.Writer
}

func (w serializedSessionOutput) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.target.Write(data)
}
