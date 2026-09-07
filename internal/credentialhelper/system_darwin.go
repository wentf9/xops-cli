//go:build darwin

package credentialhelper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
)

type darwinNativeStore struct {
	storeID  string
	toolPath string
	timeout  time.Duration
	readOnly bool
}

func newNativeSystemStore(storeID string, cfg SystemStoreConfig) (credential.Store, error) {
	toolPath, err := exec.LookPath("/usr/bin/security")
	if err != nil {
		toolPath, err = exec.LookPath("security")
		if err != nil {
			return nil, fmt.Errorf("%w: macOS security command not found", credential.ErrCredentialStoreUnavailable)
		}
	}

	return &darwinNativeStore{
		storeID:  storeID,
		toolPath: toolPath,
		timeout:  cfg.Timeout,
		readOnly: cfg.ReadOnly,
	}, nil
}

func (s *darwinNativeStore) StoreID() string {
	return s.storeID
}

func (s *darwinNativeStore) IsReadOnly() bool {
	return s.readOnly
}

func (s *darwinNativeStore) Get(ctx context.Context, ref credential.Ref) (credential.Secret, error) {
	service := fmt.Sprintf("xops:%s", ref.StoreID)
	account := ref.ItemID
	args := []string{"find-generic-password", "-s", service, "-a", account, "-w"}
	stdout, stderr, err := s.execCmd(ctx, args)
	if err != nil {
		stderrLower := strings.ToLower(stderr)
		if strings.Contains(stderrLower, "could not be found") || strings.Contains(stderrLower, "44") {
			return credential.Secret{}, credential.ErrCredentialNotFound
		}
		if strings.Contains(stderrLower, "locked") || strings.Contains(stderrLower, "user interaction is not allowed") {
			return credential.Secret{}, credential.ErrCredentialStoreLocked
		}
		return credential.Secret{}, fmt.Errorf("keychain find failed: %w", err)
	}

	secVal := bytes.TrimRight(stdout, "\r\n")
	if len(secVal) == 0 {
		return credential.Secret{}, credential.ErrCredentialNotFound
	}
	return credential.NewSecret(secVal), nil
}

func (s *darwinNativeStore) Put(ctx context.Context, ref credential.Ref, secret credential.Secret) error {
	if s.readOnly {
		return credential.ErrCredentialStoreReadOnly
	}
	service := fmt.Sprintf("xops:%s", ref.StoreID)
	account := ref.ItemID
	args := []string{"add-generic-password", "-s", service, "-a", account, "-w", string(secret.Value), "-U"}
	_, stderr, err := s.execCmd(ctx, args)
	if err != nil {
		stderrLower := strings.ToLower(stderr)
		if strings.Contains(stderrLower, "locked") {
			return fmt.Errorf("%w: %s", credential.ErrCredentialStoreLocked, stderr)
		}
		return fmt.Errorf("keychain add failed: %w", err)
	}
	return nil
}

func (s *darwinNativeStore) Delete(ctx context.Context, ref credential.Ref) error {
	if s.readOnly {
		return credential.ErrCredentialStoreReadOnly
	}
	service := fmt.Sprintf("xops:%s", ref.StoreID)
	account := ref.ItemID
	args := []string{"delete-generic-password", "-s", service, "-a", account}
	_, stderr, err := s.execCmd(ctx, args)
	if err != nil {
		stderrLower := strings.ToLower(stderr)
		if strings.Contains(stderrLower, "could not be found") || strings.Contains(stderrLower, "44") {
			return credential.ErrCredentialNotFound
		}
		return fmt.Errorf("keychain delete failed: %w", err)
	}
	return nil
}

func (s *darwinNativeStore) execCmd(ctx context.Context, args []string) ([]byte, string, error) {
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

	stdoutLimiter := &limitedBuffer{limit: MaxResponseBytes}
	stderrLimiter := &limitedBuffer{limit: MaxStderrBytes}
	cmd.Stdout = stdoutLimiter
	cmd.Stderr = stderrLimiter

	session, err := startProcessSession(cmd)
	if err != nil {
		return nil, "", err
	}
	defer func() {
		_ = session.Close()
	}()

	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-execCtx.Done():
			_ = session.KillTree()
		case <-done:
		}
	}()

	runErr := cmd.Wait()
	sanitizedStderr := SanitizeDiagnostic(stderrLimiter.buf.String())

	if execCtx.Err() != nil {
		_ = session.KillTree()
		if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
			return nil, sanitizedStderr, fmt.Errorf("%w: security command timed out after %v", credential.ErrCredentialStoreUnavailable, timeout)
		}
		return nil, sanitizedStderr, fmt.Errorf("security command canceled: %w", execCtx.Err())
	}

	if runErr != nil && !errors.Is(runErr, exec.ErrWaitDelay) {
		return nil, sanitizedStderr, runErr
	}

	return stdoutLimiter.buf.Bytes(), sanitizedStderr, nil
}

func checkPlatformSystemAvailability() error {
	return nil
}
