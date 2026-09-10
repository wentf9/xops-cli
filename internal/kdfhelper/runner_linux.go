//go:build linux && amd64

package kdfhelper

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type boundedOutput struct {
	data   []byte
	max    int
	cancel context.CancelCauseFunc
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.max-len(b.data) {
		b.cancel(ErrProtocol)
		return 0, ErrProtocol
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

// Derive accepts a response only after clean EOF, zero exit and live context.
func (r Runner) Derive(ctx context.Context, req Request) ([]byte, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate KDF executable: %w", err)
	}
	return r.run(ctx, req, executable, []string{PrivateArgument})
}

func (r Runner) run(ctx context.Context, req Request, executable string, args []string) (key []byte, err error) {
	defer func() {
		err = withCause(err, context.Cause(ctx))
		if err != nil {
			clear(key)
			key = nil
		}
	}()
	wire, err := req.MarshalBinary()
	if err != nil {
		return nil, err
	}
	defer clear(wire)
	if err := memoryPreflight(); err != nil {
		return nil, err
	}
	timeout, err := processTimeout(ctx, r.Timeout)
	if err != nil {
		return nil, err
	}
	bounded, cancelDeadline := context.WithTimeout(ctx, timeout)
	defer cancelDeadline()
	work, cancel := context.WithCancelCause(bounded)
	defer cancel(context.Canceled)
	defer func() { err = withCause(err, context.Cause(work)) }()
	group, err := createLimit(r.CgroupParent)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, removeLimit(group)) }()
	stdout := &boundedOutput{max: MaxResponseBytes, cancel: cancel}
	stderr := &boundedOutput{max: 4096, cancel: cancel}
	defer func() { clear(stdout.data); clear(stderr.data) }()
	cmd := exec.CommandContext(work, executable, args...)
	cmd.Env = []string{"GOMAXPROCS=1", "GOMEMLIMIT=96MiB", "XOPS_INTERNAL_KDF_TIMEOUT=" + timeout.String()}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	// The worker blocks on request input until a requested cgroup is installed.
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("create KDF input: %w", err)
	}
	defer func() {
		closeErr := input.Close()
		if closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
			err = errors.Join(err, closeErr)
		}
	}()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = 100 * time.Millisecond
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
	// Linux Pdeathsig follows the creating OS thread, so keep it alive until Wait.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start private KDF: %w", errors.Join(ErrProcess, err))
	}
	if group != "" {
		if e := os.WriteFile(filepath.Join(group, "cgroup.procs"), []byte(strconv.Itoa(cmd.Process.Pid)), 0600); e != nil {
			cancel(errors.Join(ErrResource, e))
		}
	}
	writeDone := make(chan error, 1)
	go func() { writeDone <- sendRequest(work, input, wire) }()
	// Observe without reaping, so the group leader's PID cannot be reused before
	// killing possible inherited-pipe descendants. Cmd.Wait performs the reap.
	killErr := finishProcessGroup(cmd, cancel)
	waitErr := cmd.Wait()
	closeErr := input.Close()
	if errors.Is(closeErr, os.ErrClosed) {
		closeErr = nil
	}
	writeErr := <-writeDone
	resourceErr := limitFailure(group)
	if cause := context.Cause(work); cause != nil {
		return nil, errors.Join(cause, killErr, closeErr, resourceErr)
	}
	return processResponse(stdout.data, errors.Join(waitErr, writeErr, killErr, closeErr, resourceErr))
}

func withCause(err, cause error) error {
	if cause != nil && !errors.Is(err, cause) {
		return errors.Join(err, cause)
	}
	return err
}

func processTimeout(ctx context.Context, configured time.Duration) (time.Duration, error) {
	if err := context.Cause(ctx); err != nil {
		return 0, err
	}
	if configured < 0 {
		return 0, ErrProtocol
	}
	if configured > 0 {
		return configured, nil
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, context.DeadlineExceeded
		}
		return remaining, nil
	}
	return 30 * time.Second, nil
}

func limitFailure(path string) error {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(path, "memory.events"))
	if err != nil {
		return errors.Join(ErrResource, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "oom_kill" {
			continue
		}
		n, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return ErrResource
		}
		if n > 0 {
			return ErrResource
		}
	}
	return nil
}

func processResponse(data []byte, processErr error) ([]byte, error) {
	response, err := ParseResponse(data)
	if err != nil {
		return nil, errors.Join(err, processErr)
	}
	if response.Status != Success {
		response.Zero()
		kind := ErrProcess
		switch response.Status {
		case InvalidRequest:
			kind = ErrProtocol
		case UnsupportedVersion:
			kind = ErrUnsupported
		case ResourceFailure:
			kind = ErrResource
		}
		return nil, errors.Join(kind, processErr)
	}
	if processErr != nil {
		response.Zero()
		return nil, errors.Join(ErrProcess, processErr)
	}
	return response.Key, nil
}

func finishProcessGroup(cmd *exec.Cmd, cancel context.CancelCauseFunc) error {
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, cmd.Process.Pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			cancel(errors.Join(ErrProcess, err))
			return err
		}
		break
	}
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

func removeLimit(path string) error {
	if path == "" {
		return nil
	}
	return os.Remove(path)
}

func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}

func sendRequest(ctx context.Context, out io.WriteCloser, b []byte) error {
	if cause := context.Cause(ctx); cause != nil {
		return errors.Join(cause, out.Close())
	}
	n, err := out.Write(b)
	if err == nil && n != len(b) {
		err = ErrProtocol
	}
	return errors.Join(err, out.Close())
}

func memoryPreflight() error {
	available, observed := memorySnapshot()
	if observed && available < 96*1024*1024 {
		return ErrResource
	}
	return nil
}

func memorySnapshot() (available uint64, observed bool) {
	b, err := os.ReadFile("/proc/meminfo")
	if err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 3 && fields[0] == "MemAvailable:" {
				n, e := strconv.ParseUint(fields[1], 10, 64)
				if e == nil && n <= ^uint64(0)/1024 {
					available = n * 1024
					observed = true
				}
			}
		}
	}
	b, err = os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return available, observed
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "0::/") {
			continue
		}
		relative := strings.TrimPrefix(line, "0::/")
		if relative != "" && (filepath.Clean(relative) != relative || strings.HasPrefix(relative, "..")) {
			continue
		}
		root := "/sys/fs/cgroup"
		path := filepath.Join(root, relative)
		for {
			maximum, maxErr := os.ReadFile(filepath.Join(path, "memory.max"))
			current, curErr := os.ReadFile(filepath.Join(path, "memory.current"))
			if maxErr == nil && curErr == nil {
				if free, ok := cgroupRemaining(string(maximum), string(current)); ok && (!observed || free < available) {
					available = free
					observed = true
				}
			}
			if path == root {
				break
			}
			path = filepath.Dir(path)
		}
	}
	return available, observed
}

func cgroupRemaining(maximum, current string) (uint64, bool) {
	limit, err := strconv.ParseUint(strings.TrimSpace(maximum), 10, 64)
	if err != nil {
		return 0, false
	}
	used, err := strconv.ParseUint(strings.TrimSpace(current), 10, 64)
	if err != nil {
		return 0, false
	}
	if used >= limit {
		return 0, true
	}
	return limit - used, true
}

func createLimit(parent string) (path string, err error) {
	if parent == "" {
		return "", nil
	}
	if !filepath.IsAbs(parent) || filepath.Clean(parent) != parent {
		return "", ErrResource
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(parent, &fs); err != nil {
		return "", errors.Join(ErrResource, err)
	}
	if fs.Type != 0x63677270 {
		return "", ErrResource
	} // cgroup v2, never ordinary files
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() {
		return "", errors.Join(ErrResource, err)
	}
	path, err = os.MkdirTemp(parent, "xops-kdf-")
	if err != nil {
		return "", fmt.Errorf("create delegated KDF limit: %w", errors.Join(ErrResource, err))
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.Remove(path))
		}
	}()
	for name, value := range map[string]string{"memory.max": "134217728", "memory.swap.max": "0"} {
		file := filepath.Join(path, name)
		if err := os.WriteFile(file, []byte(value), 0600); err != nil {
			return path, errors.Join(ErrResource, err)
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return path, errors.Join(ErrResource, err)
		}
		if strings.TrimSpace(string(b)) != value {
			return path, ErrResource
		}
	}
	return path, nil
}
