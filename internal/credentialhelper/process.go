package credentialhelper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
)

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

	execCtx := ctx
	var cancel context.CancelFunc
	if opts.Timeout > 0 {
		execCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	args := make([]string, 0, len(opts.Args)+1)
	args = append(args, opts.Args...)
	args = append(args, string(action))

	cmd := exec.CommandContext(execCtx, opts.Command, args...)
	if len(opts.Env) > 0 {
		cmd.Env = append(os.Environ(), opts.Env...)
	}
	configureProcessIsolation(cmd)

	// 序列化请求到 stdin 缓冲
	var stdinBuf bytes.Buffer
	if err := EncodeRequest(&stdinBuf, req); err != nil {
		return nil, err
	}
	cmd.Stdin = &stdinBuf

	stdoutLimiter := &limitedBuffer{limit: MaxResponseBytes}
	stderrLimiter := &limitedBuffer{limit: MaxStderrBytes}
	cmd.Stdout = stdoutLimiter
	cmd.Stderr = stderrLimiter

	runErr := cmd.Run()

	// 优先检查超时或取消
	if execCtx.Err() != nil {
		if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w: credential helper timed out after %v", credential.ErrCredentialStoreUnavailable, opts.Timeout)
		}
		return nil, fmt.Errorf("credential helper canceled: %w", execCtx.Err())
	}

	// 检查 stdout 超限
	if stdoutLimiter.total > MaxResponseBytes {
		return nil, fmt.Errorf("credential helper response exceeded maximum limit of %d bytes", MaxResponseBytes)
	}

	// 若 stdout 有输出，先尝试解码（无论子进程退出码是否为 0，因为部分 helper 在报错时以非 0 退出并输出 JSON 错误）
	if stdoutLimiter.buf.Len() > 0 {
		resp, parseErr := DecodeResponse(&stdoutLimiter.buf)
		if parseErr != nil {
			// 若返回了标准协议错误代码（如 not-found, locked 等），优先向上传播该语义错误
			if resp != nil && strings.TrimSpace(resp.Code) != "" {
				return resp, parseErr
			}
			// 若无法解析出有效 JSON，且进程退出报错
			if runErr != nil {
				stderrMsg := formatStderr(stderrLimiter.buf.String())
				if stderrMsg != "" {
					return nil, fmt.Errorf("credential helper failed (%w): %s", runErr, stderrMsg)
				}
				return nil, fmt.Errorf("credential helper failed: %w", runErr)
			}
			return nil, parseErr
		}
		return resp, nil
	}

	// stdout 为空且报错
	if runErr != nil {
		stderrMsg := formatStderr(stderrLimiter.buf.String())
		if stderrMsg != "" {
			return nil, fmt.Errorf("credential helper failed (%w): %s", runErr, stderrMsg)
		}
		return nil, fmt.Errorf("credential helper failed: %w", runErr)
	}

	return nil, fmt.Errorf("empty response from credential helper")
}

func formatStderr(raw string) string {
	msg := strings.TrimSpace(raw)
	if len(msg) > 512 {
		return msg[:512] + "..."
	}
	return msg
}
