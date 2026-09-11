//go:build (darwin || windows) && (amd64 || arm64)

package kdfhelper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"
)

type privateOutput struct {
	data   []byte
	limit  int
	cancel context.CancelFunc
}

func (b *privateOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-len(b.data) {
		b.cancel()
		return 0, ErrProtocol
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func (r Runner) Derive(ctx context.Context, req Request) (key []byte, err error) {
	defer func() {
		err = withCause(err, context.Cause(ctx))
		if err != nil {
			clear(key)
			key = nil
		}
	}()
	if r.CgroupParent != "" {
		return nil, fmt.Errorf("cgroup limits are Linux-only: %w", ErrUnsupported)
	}
	wire, err := req.MarshalBinary()
	if err != nil {
		return nil, err
	}
	defer clear(wire)
	timeout, err := processTimeout(ctx, r.Timeout)
	if err != nil {
		return nil, err
	}
	work, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(work, exe, PrivateArgument)
	cmd.Env = []string{"GOMAXPROCS=1", "GOMEMLIMIT=96MiB", "XOPS_INTERNAL_KDF_TIMEOUT=" + timeout.String(), "XOPS_INTERNAL_KDF_PARENT=" + strconv.Itoa(os.Getpid())}
	cmd.WaitDelay = 100 * time.Millisecond
	stdout := &privateOutput{limit: MaxResponseBytes, cancel: cancel}
	stderr := &privateOutput{limit: 4096, cancel: cancel}
	defer func() { clear(stdout.data); clear(stderr.data) }()
	cmd.Stdout, cmd.Stderr = stdout, stderr
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	defer func() {
		if e := input.Close(); e != nil && !errors.Is(e, os.ErrClosed) {
			err = errors.Join(err, e)
		}
	}()
	cleanup, err := preparePrivateProcess(cmd)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, cleanup())
		if err != nil {
			clear(key)
			key = nil
		}
	}()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start private KDF: %w", errors.Join(ErrProcess, err))
	}
	if err := attachPrivateProcess(cmd); err != nil {
		killErr := cmd.Process.Kill()
		waitErr := cmd.Wait()
		return nil, errors.Join(ErrProcess, err, killErr, waitErr)
	}
	writeDone := make(chan error, 1)
	go func() { _, e := input.Write(wire); writeDone <- errors.Join(e, input.Close()) }()
	waitErr := cmd.Wait()
	writeErr := <-writeDone
	if work.Err() != nil {
		return nil, errors.Join(work.Err(), waitErr, writeErr)
	}
	return processResponse(stdout.data, errors.Join(waitErr, writeErr))
}

func memorySnapshot() (uint64, bool) { return 0, false }
