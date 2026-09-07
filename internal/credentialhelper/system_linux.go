//go:build linux

package credentialhelper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
)

type linuxNativeStore struct {
	storeID  string
	toolPath string
	timeout  time.Duration
	readOnly bool
}

func newNativeSystemStore(storeID string, cfg SystemStoreConfig) (credential.Store, error) {
	if err := checkPlatformSystemAvailability(); err != nil {
		return nil, err
	}

	toolPath, err := exec.LookPath("secret-tool")
	if err != nil {
		if cmdPath, args, env, helperErr := resolveControlledSystemHelper(); helperErr == nil {
			opts := ProcessOptions{
				Command: cmdPath,
				Args:    args,
				Env:     env,
				Timeout: cfg.Timeout,
			}
			return NewHelperStore(storeID, opts, cfg.ReadOnly)
		}
		return nil, fmt.Errorf("%w: secret-tool executable not found in PATH and no external helper configured", credential.ErrCredentialStoreUnavailable)
	}

	return &linuxNativeStore{
		storeID:  storeID,
		toolPath: toolPath,
		timeout:  cfg.Timeout,
		readOnly: cfg.ReadOnly,
	}, nil
}

func (s *linuxNativeStore) StoreID() string {
	return s.storeID
}

func (s *linuxNativeStore) IsReadOnly() bool {
	return s.readOnly
}

func (s *linuxNativeStore) Get(ctx context.Context, ref credential.Ref) (credential.Secret, error) {
	args := []string{"lookup", "xops-store", ref.StoreID, "xops-item", ref.ItemID}
	stdout, stderr, err := s.execCmd(ctx, args, nil)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return credential.Secret{}, context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, credential.ErrCredentialStoreUnavailable) || errors.Is(err, credential.ErrCredentialStoreLocked) {
			return credential.Secret{}, err
		}
		stderrLower := strings.ToLower(stderr)
		if strings.Contains(stderrLower, "locked") {
			return credential.Secret{}, fmt.Errorf("%w: %s", credential.ErrCredentialStoreLocked, stderr)
		}
		if stderr != "" {
			return credential.Secret{}, fmt.Errorf("%w: secret-tool lookup failed: %s", credential.ErrCredentialStoreUnavailable, stderr)
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return credential.Secret{}, credential.ErrCredentialNotFound
		}
		return credential.Secret{}, fmt.Errorf("%w: secret-tool lookup failed: %w", credential.ErrCredentialStoreUnavailable, err)
	}

	if len(stdout) == 0 {
		return credential.Secret{}, credential.ErrCredentialNotFound
	}

	return credential.NewSecret(stdout), nil
}

func (s *linuxNativeStore) Put(ctx context.Context, ref credential.Ref, secret credential.Secret) error {
	if s.readOnly {
		return credential.ErrCredentialStoreReadOnly
	}
	label := fmt.Sprintf("xops:%s/%s", ref.StoreID, ref.ItemID)
	args := []string{"store", "--label=" + label, "xops-store", ref.StoreID, "xops-item", ref.ItemID}
	_, stderr, err := s.execCmd(ctx, args, secret.Value)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, credential.ErrCredentialStoreUnavailable) || errors.Is(err, credential.ErrCredentialStoreLocked) {
			return err
		}
		if strings.Contains(strings.ToLower(stderr), "locked") {
			return fmt.Errorf("%w: %s", credential.ErrCredentialStoreLocked, stderr)
		}
		if stderr != "" {
			return fmt.Errorf("%w: secret-tool store failed: %s", credential.ErrCredentialStoreUnavailable, stderr)
		}
		return fmt.Errorf("secret-tool store failed: %w", err)
	}
	return nil
}

func (s *linuxNativeStore) Delete(ctx context.Context, ref credential.Ref) error {
	if s.readOnly {
		return credential.ErrCredentialStoreReadOnly
	}
	args := []string{"clear", "xops-store", ref.StoreID, "xops-item", ref.ItemID}
	_, stderr, err := s.execCmd(ctx, args, nil)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, credential.ErrCredentialStoreUnavailable) || errors.Is(err, credential.ErrCredentialStoreLocked) {
			return err
		}
		if strings.Contains(strings.ToLower(stderr), "locked") {
			return fmt.Errorf("%w: %s", credential.ErrCredentialStoreLocked, stderr)
		}
		if stderr != "" {
			return fmt.Errorf("%w: secret-tool clear failed: %s", credential.ErrCredentialStoreUnavailable, stderr)
		}
		return fmt.Errorf("secret-tool clear failed: %w", err)
	}
	return nil
}

func (s *linuxNativeStore) execCmd(ctx context.Context, args []string, stdinData []byte) ([]byte, string, error) {
	timeout := s.timeout
	if timeout <= 0 {
		timeout = DefaultHelperTimeout
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, s.toolPath, args...)
	waitDelay := DefaultProcessWaitDelay
	if timeout < waitDelay {
		waitDelay = timeout
	}
	cmd.WaitDelay = waitDelay

	if len(stdinData) > 0 {
		cmd.Stdin = bytes.NewReader(stdinData)
	}

	stdoutLimiter := &limitedBuffer{limit: MaxResponseBytes}
	stderrLimiter := &limitedBuffer{limit: MaxStderrBytes}
	cmd.Stdout = stdoutLimiter
	cmd.Stderr = stderrLimiter

	session, err := startProcessSession(cmd)
	if err != nil {
		if isNotFoundErr(err) {
			return nil, "", fmt.Errorf("%w: %w", credential.ErrCredentialStoreUnavailable, err)
		}
		return nil, "", err
	}
	defer func() {
		_ = session.Close()
	}()

	cancelDone := make(chan struct{})
	var cancelWg sync.WaitGroup
	cancelWg.Add(1)

	go func() {
		defer cancelWg.Done()
		select {
		case <-execCtx.Done():
			_ = session.KillTree()
		case <-cancelDone:
		}
	}()

	runErr := cmd.Wait()
	close(cancelDone)
	cancelWg.Wait()

	sanitizedStderr := SanitizeDiagnostic(stderrLimiter.buf.String(), string(stdinData))

	if execCtx.Err() != nil {
		_ = session.KillTree()
		if errors.Is(execCtx.Err(), context.Canceled) {
			return nil, sanitizedStderr, context.Canceled
		}
		if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
			return nil, sanitizedStderr, fmt.Errorf("%w: secret-tool timed out after %v", credential.ErrCredentialStoreUnavailable, timeout)
		}
		return nil, sanitizedStderr, execCtx.Err()
	}

	// 严格检查 stdout 输出上限
	if stdoutLimiter.total > MaxResponseBytes {
		return nil, sanitizedStderr, fmt.Errorf("%w: secret-tool output exceeded maximum limit of %d bytes", credential.ErrCredentialStoreUnavailable, MaxResponseBytes)
	}

	if runErr != nil && isNotFoundErr(runErr) {
		return nil, sanitizedStderr, fmt.Errorf("%w: %w", credential.ErrCredentialStoreUnavailable, runErr)
	}

	if runErr != nil {
		return nil, sanitizedStderr, runErr
	}

	return stdoutLimiter.buf.Bytes(), sanitizedStderr, nil
}

func checkPlatformSystemAvailability() error {
	// Linux Secret Service 强依赖桌面 D-Bus 会话
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" && os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return fmt.Errorf("%w: system credential store unavailable in headless environment without D-Bus session", credential.ErrCredentialStoreUnavailable)
	}
	return nil
}

func handlePlatformSystemHelper(action Action, req *Request) (*Response, int) {
	return &Response{Code: "unavailable", Message: "native helper protocol on linux not implemented directly, uses secret-tool"}, 1
}
