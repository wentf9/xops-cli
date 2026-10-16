package ssh

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
)

// OutputError marks a failed output write. Hosts must not report it back to
// the same possibly blocked sink. Unwrap preserves cancellation and I/O causes.
type OutputError struct {
	Target io.Writer // Borrowed sink identity; never closed by the error owner.
	Err    error
}

// TargetsFile matches the original file even when serialized by LockedWriter.
// It compares file objects, without probing handles or consulting global stdio.
func (e *OutputError) TargetsFile(file *os.File) bool {
	target := e.Target
	for {
		locked, ok := target.(*LockedWriter)
		if !ok {
			return target == file
		}
		if locked == nil {
			return false
		}
		target = locked.w
	}
}

func (e *OutputError) Error() string { return "write command output: " + e.Err.Error() }
func (e *OutputError) Unwrap() error { return e.Err }

// regularFileOutput borrows a local regular file. The kernel does not allow a
// blocked regular-file write to be interrupted, so cancellation is checked
// before every write and a write already in progress completes first.
type regularFileOutput struct{ file *os.File }

func (w regularFileOutput) WriteContext(ctx context.Context, data []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return w.file.Write(data)
}

// isNullDevice reports the platform null device, whose writes never block but
// which cannot register for deadlines like other character devices.
func isNullDevice(info os.FileInfo) bool {
	// Windows device/pipe FileInfo values may all carry zero file IDs.
	// Its platform binding identifies NUL by kernel object name instead.
	if runtime.GOOS == "windows" || info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	null, err := os.Stat(os.DevNull)
	return err == nil && os.SameFile(info, null)
}

// BindOutput prepares a non-PTY command output sink so that canceling ctx does
// not leave the SSH session waiting for a blocked write.
//
// ContextWriter implementations, finite memory sinks, io.Discard, the null
// device, local regular files, and native terminal/pipe adapters bind to ctx.
// Linux and macOS terminal adapters use owned nonblocking handles; macOS also
// accepts already nonblocking pipes. Windows synchronous/overlapped pipes use
// owned duplicate handles with thread/request-specific cancellation. The caller's
// file is never closed and its flags or console modes are not modified. macOS
// blocking pipes and Windows consoles remain unsupported. Unlike PTY output, no
// per-write idle limit is applied, so a slow consumer such as a pager is not
// treated as a failure; only ctx cancellation or its deadline interrupts a write.
//
// Any other writer is returned unchanged with cancelable=false: arbitrary
// Write callbacks cannot be interrupted, and wrapping them in a goroutine would
// merely hide the leak. The caller owns that writer and must keep it
// non-blocking. closeFn must be called after all writes have finished and
// releases only resources created by BindOutput.
func BindOutput(ctx context.Context, target io.Writer) (writer io.Writer, closeFn func() error, cancelable bool, err error) {
	noop := func() error { return nil }
	if ctx == nil {
		return nil, noop, false, fmt.Errorf("bind command output: context is nil")
	}
	if target == nil {
		return nil, noop, false, nil
	}
	if nilCapability(target) {
		return nil, noop, false, fmt.Errorf("bind command output: output is nil")
	}
	if locked, ok := target.(*LockedWriter); ok {
		if locked.mu == nil {
			return nil, noop, false, fmt.Errorf("bind command output: output mutex is nil")
		}
		bound, closeBound, supported, bindErr := BindOutput(ctx, locked.w)
		if bindErr != nil || !supported {
			return target, closeBound, supported, bindErr
		}
		return lockedOutputBinding{ctx, locked, bound}, closeBound, true, nil
	}
	if file, ok := target.(*os.File); ok {
		info, statErr := file.Stat()
		if statErr == nil && (info.Mode().IsRegular() || isNullDevice(info)) {
			return contextOutput{ctx, regularFileOutput{file}, file}, noop, true, nil
		}
	}
	bound, closeBound, bindErr := prepareContextOutputWithLimit(ctx, target, 0)
	if bindErr != nil {
		return target, noop, false, nil
	}
	return bound, closeBound, true, nil
}

// bindRunOutput binds the external sink selected by config. Buffered modes
// retain their own finite memory and require no bridge.
func (c *Client) bindRunOutput(ctx context.Context, config *RunConfig) (*RunConfig, func() error, error) {
	bound := *config
	noop := func() error { return nil }
	switch config.OutMode {
	case OutputModeStream:
		writer, closeFn, cancelable, err := BindOutput(ctx, config.StreamWriter)
		if err != nil {
			return nil, nil, err
		}
		c.logUncancelableOutput(cancelable, config.StreamWriter)
		bound.StreamWriter = writer
		return &bound, closeFn, nil
	case OutputModeFile:
		if config.OutFile == nil {
			return &bound, noop, nil
		}
		writer, closeFn, cancelable, err := BindOutput(ctx, config.OutFile)
		if err != nil {
			return nil, nil, err
		}
		c.logUncancelableOutput(cancelable, config.OutFile)
		bound.fileOutput = writer
		return &bound, closeFn, nil
	default:
		return &bound, noop, nil
	}
}

func (c *Client) logUncancelableOutput(cancelable bool, target io.Writer) {
	if !cancelable && target != nil {
		c.getLogger().Debugf("command output %T cannot be canceled; the caller must keep writes non-blocking", target)
	}
}
