package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"golang.org/x/term"
)

const diagnosticCapacity = 128

// diagnosticTerminal never calls File.Fd, which can clear borrowed O_NONBLOCK
// and invalidate a macOS output binding sharing the pipe description.
func diagnosticTerminal(file *os.File) bool {
	if file == nil {
		return false
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return false
	}
	terminal := false
	err = raw.Control(func(fd uintptr) { terminal = term.IsTerminal(int(fd)) })
	return err == nil && terminal
}

// diagnosticOutput replaces SCP's private output queue. Commands own it until
// all event producers stop. The target is borrowed; callbacks never do sink I/O.
// Unsupported bindings disable auxiliary output, without a raw-write fallback.
type diagnosticOutput struct {
	mu          sync.Mutex
	lines       chan string
	dropped     int
	closed      bool
	disabled    bool
	stream      string
	label       string
	target      io.Writer
	writer      io.Writer
	cancel      context.CancelFunc
	closeOutput func() error
	done        chan error
	finishOnce  sync.Once
	finishErr   error
}

func newDiagnosticOutput(ctx context.Context, target io.Writer, stream, label string, gates ...chan struct{}) (*diagnosticOutput, error) {
	outputCtx, cancel := context.WithCancel(ctx)
	writer, closeOutput, supported, err := ssh.BindOutput(outputCtx, target)
	if err != nil {
		cancel()
		return nil, &ssh.OutputError{Target: target, Err: err}
	}
	d := &diagnosticOutput{lines: make(chan string, diagnosticCapacity), disabled: !supported,
		stream: stream, label: label, target: target, writer: writer, cancel: cancel,
		closeOutput: closeOutput, done: make(chan error, 1)}
	if supported {
		go func() {
			var outputErr error
			for line := range d.lines {
				if outputErr == nil {
					acquired := false
					if len(gates) > 0 && gates[0] != nil {
						select {
						case <-outputCtx.Done():
							outputErr = outputCtx.Err()
						case <-gates[0]:
							acquired = true
						}
					}
					if outputErr == nil {
						timer := time.AfterFunc(time.Second, cancel)
						_, outputErr = io.WriteString(writer, line)
						timer.Stop()
					}
					if acquired {
						gates[0] <- struct{}{}
					}
				}
			}
			d.done <- outputErr
		}()
	}
	return d, nil
}

func (d *diagnosticOutput) enqueue(line string) {
	if d.disabled {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	select {
	case d.lines <- line:
	default:
		d.dropped++
	}
}

func (d *diagnosticOutput) Write(p []byte) (int, error) {
	d.enqueue(string(p))
	return len(p), nil
}

// finish joins the writer and releases only owned resources. It is idempotent;
// ordinary-file writes still have to return from the kernel before this can end.
func (d *diagnosticOutput) finish() error {
	d.finishOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		close(d.lines)
		dropped := d.dropped
		d.mu.Unlock()
		var err error
		if !d.disabled {
			err = <-d.done
		}
		if !d.disabled && dropped > 0 && err == nil {
			timer := time.AfterFunc(time.Second, d.cancel)
			_, err = fmt.Fprintf(d.writer, "%s: output buffer full; omitted %d updates\n", d.label, dropped)
			timer.Stop()
		}
		d.cancel()
		err = errors.Join(err, d.closeOutput())
		if err != nil {
			d.finishErr = &ssh.OutputError{Target: d.target, Err: err}
		}
	})
	return d.finishErr
}
