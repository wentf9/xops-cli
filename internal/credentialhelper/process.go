package credentialhelper

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
)

// DefaultHelperTimeout 是 credential helper 进程执行的默认超时时间。
const DefaultHelperTimeout = 30 * time.Second

// DefaultProcessWaitDelay 是主进程退出后等待继承管道的子孙进程排空的最大窗口。
const DefaultProcessWaitDelay = 50 * time.Millisecond

// ProcessOptions 包含启动子进程 credential helper 的选项。
type ProcessOptions struct {
	Command string
	Args    []string
	Env     []string
	Timeout time.Duration
}

type limitedBuffer struct {
	buf   bytes.Buffer
	limit int
	total int
}

func (l *limitedBuffer) Write(p []byte) (n int, err error) {
	l.total += len(p)
	remaining := l.limit - l.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = l.buf.Write(p[:remaining])
		} else {
			_, _ = l.buf.Write(p)
		}
	}
	return len(p), nil
}

// Run 启动 credential helper 子进程，传递 stdin 并解析 stdout 响应。
func Run(ctx context.Context, opts ProcessOptions, action Action, req *Request) (*Response, error) {
	if strings.TrimSpace(opts.Command) == "" {
		return nil, fmt.Errorf("credential helper command is empty")
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultHelperTimeout
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd, stdoutLimiter, stderrLimiter, err := buildProcessCmd(execCtx, opts, action, req, timeout)
	if err != nil {
		return nil, err
	}

	session, err := startProcessSession(execCtx, cmd)
	if err != nil {
		if execCtx.Err() != nil {
			if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
				return nil, fmt.Errorf("%w: credential helper timed out after %v: %w", credential.ErrCredentialStoreUnavailable, timeout, execCtx.Err())
			}
			return nil, fmt.Errorf("credential helper canceled: %w", execCtx.Err())
		}
		if isNotFoundErr(err) {
			return nil, fmt.Errorf("%w: credential helper executable not found: %s", credential.ErrCredentialStoreUnavailable, opts.Command)
		}
		return nil, fmt.Errorf("start credential helper failed: %w", err)
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

	sensitive := collectSensitiveTokens(req)
	sanitizedStderr := SanitizeDiagnostic(stderrLimiter.buf.String(), sensitive...)

	if execCtx.Err() != nil {
		_ = session.KillTree()
		if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w: credential helper timed out after %v: %w", credential.ErrCredentialStoreUnavailable, timeout, execCtx.Err())
		}
		return nil, fmt.Errorf("credential helper canceled: %w", execCtx.Err())
	}

	if stdoutLimiter.total > MaxResponseBytes {
		return nil, fmt.Errorf("%w: credential helper response exceeded maximum limit of %d bytes", credential.ErrCredentialStoreUnavailable, MaxResponseBytes)
	}

	if runErr != nil && isNotFoundErr(runErr) {
		return nil, fmt.Errorf("%w: credential helper executable not found: %s", credential.ErrCredentialStoreUnavailable, opts.Command)
	}

	return parseOutputResponse(stdoutLimiter, runErr, sanitizedStderr, sensitive)
}

func buildProcessCmd(execCtx context.Context, opts ProcessOptions, action Action, req *Request, timeout time.Duration) (*exec.Cmd, *limitedBuffer, *limitedBuffer, error) {
	args := make([]string, 0, len(opts.Args)+1)
	args = append(args, opts.Args...)
	args = append(args, string(action))

	cmd := exec.CommandContext(execCtx, opts.Command, args...)
	if len(opts.Env) > 0 {
		cmd.Env = append(os.Environ(), opts.Env...)
	}

	waitDelay := DefaultProcessWaitDelay
	if timeout < waitDelay {
		waitDelay = timeout
	}
	cmd.WaitDelay = waitDelay

	var stdinBuf bytes.Buffer
	if err := EncodeRequest(&stdinBuf, req); err != nil {
		return nil, nil, nil, err
	}
	cmd.Stdin = &stdinBuf

	stdoutLimiter := &limitedBuffer{limit: MaxResponseBytes}
	stderrLimiter := &limitedBuffer{limit: MaxStderrBytes}
	cmd.Stdout = stdoutLimiter
	cmd.Stderr = stderrLimiter

	return cmd, stdoutLimiter, stderrLimiter, nil
}

func collectSensitiveTokens(req *Request) []string {
	var sensitive []string
	if req != nil && req.Secret != "" {
		sensitive = append(sensitive, req.Secret)
		if decoded, decErr := base64.StdEncoding.DecodeString(req.Secret); decErr == nil && len(decoded) > 0 {
			sensitive = append(sensitive, string(decoded))
		}
	}
	return sensitive
}

func parseOutputResponse(stdoutLimiter *limitedBuffer, runErr error, sanitizedStderr string, sensitive []string) (*Response, error) {
	if stdoutLimiter.buf.Len() > 0 {
		resp, parseErr := DecodeResponse(&stdoutLimiter.buf)
		if resp != nil && strings.TrimSpace(resp.Message) != "" {
			resp.Message = SanitizeDiagnostic(resp.Message, sensitive...)
		}
		if resp != nil && strings.TrimSpace(resp.Code) != "" {
			return resp, MapErrorCode(resp.Code, resp.Message)
		}
		if parseErr != nil {
			if runErr != nil {
				if sanitizedStderr != "" {
					return nil, fmt.Errorf("credential helper failed (%w): %s", runErr, sanitizedStderr)
				}
				return nil, fmt.Errorf("credential helper failed: %w", runErr)
			}
			return nil, parseErr
		}

		if runErr != nil {
			if sanitizedStderr != "" {
				return nil, fmt.Errorf("credential helper failed with exit code (%w): %s", runErr, sanitizedStderr)
			}
			return nil, fmt.Errorf("credential helper failed with exit code: %w", runErr)
		}

		return resp, nil
	}

	if runErr != nil {
		if sanitizedStderr != "" {
			return nil, fmt.Errorf("credential helper failed (%w): %s", runErr, sanitizedStderr)
		}
		return nil, fmt.Errorf("credential helper failed: %w", runErr)
	}

	return nil, fmt.Errorf("empty response from credential helper")
}

func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, exec.ErrNotFound) || os.IsNotExist(err) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such file or directory") ||
		strings.Contains(msg, "executable file not found") ||
		strings.Contains(msg, "cannot find the file")
}
