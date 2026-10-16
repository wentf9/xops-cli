package cmd

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/wentf9/xops-cli/core/ssh"
)

// writeCommandOutput owns a binding for this synchronous render only. It never
// closes the borrowed stream or starts a worker for an unsupported writer.
// Primary output retains the existing direct fallback on unsupported sinks.
func writeCommandOutput(ctx context.Context, target io.Writer, render func(io.Writer) error) (retErr error) {
	if err := ctx.Err(); err != nil {
		return &ssh.OutputError{Target: target, Err: err}
	}
	bound, closeOutput, _, err := ssh.BindOutput(ctx, target)
	if err != nil {
		return &ssh.OutputError{Target: target, Err: err}
	}
	defer func() {
		retErr = errors.Join(retErr, closeOutput())
		if retErr != nil {
			retErr = &ssh.OutputError{Target: target, Err: retErr}
		}
	}()
	return render(bound)
}

// Probe only to choose between strict and legacy SSH entry points. The probe
// owns and releases its temporary bindings; execution acquires its own bindings
// and rechecks capabilities before starting any remote command. Never retry a
// command on the legacy path after strict execution has begun.
func commandOutputSupported(ctx context.Context) (bool, error) {
	for _, target := range []*os.File{os.Stdout, os.Stderr} {
		_, release, supported, err := ssh.BindOutput(ctx, target)
		err = errors.Join(err, release())
		if err != nil {
			return false, &ssh.OutputError{Target: target, Err: err}
		}
		if !supported {
			return false, nil
		}
	}
	return true, nil
}

// HasStandardOutputError limits suppression to failures of process standard
// streams. Walk every joined cause: an independent log error must not hide a
// simultaneous standard-stream failure, or vice versa trigger suppression.
//
//nolint:errorlint // Inspect every error node; errors.As selects only the first matching sink.
func HasStandardOutputError(err error) bool {
	switch failure := err.(type) {
	case *SCPOutputError:
		if failure == nil {
			return false
		}
		if failure.Stream == "stdout" || failure.Stream == "stderr" {
			return true
		}
	case *ssh.OutputError:
		if failure == nil {
			return false
		}
		if failure.TargetsFile(os.Stdout) || failure.TargetsFile(os.Stderr) {
			return true
		}
	}
	switch cause := err.(type) {
	case interface{ Unwrap() []error }:
		for _, child := range cause.Unwrap() {
			if HasStandardOutputError(child) {
				return true
			}
		}
	case interface{ Unwrap() error }:
		return HasStandardOutputError(cause.Unwrap())
	}
	return false
}
