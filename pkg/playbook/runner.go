package playbook

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"text/template"
	"time"

	"github.com/wentf9/xops-cli/pkg/sftp"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

// runStep 根据步骤类型分发到对应执行器，并处理重试逻辑。
func (e *Engine) runStep(ctx context.Context, client *ssh.Client, step Step, globalSudo bool) StepResult {
	start := time.Now()

	useSudo := globalSudo
	if step.Sudo != nil {
		useSudo = *step.Sudo
	}

	maxAttempts := step.Retries + 1
	retryDelay := step.RetryDelay.Duration
	if retryDelay <= 0 {
		retryDelay = time.Second
	}

	var result StepResult
	for attempt := range maxAttempts {
		result = e.dispatchStep(ctx, client, step, useSudo)
		result.StepName = step.Name
		result.Duration = time.Since(start)

		if result.Status != StatusFailed {
			return result
		}

		if attempt < step.Retries {
			// 等待后重试
			select {
			case <-ctx.Done():
				result.Err = ctx.Err()
				return result
			case <-time.After(retryDelay):
			}
		}
	}

	return result
}

// dispatchStep 将步骤分发到对应的执行函数。
func (e *Engine) dispatchStep(ctx context.Context, client *ssh.Client, step Step, useSudo bool) StepResult {
	switch {
	case step.Shell != "":
		return e.runShell(ctx, client, step.Shell, useSudo)
	case step.Script != "":
		return e.runScript(ctx, client, step.Script, useSudo)
	case step.Copy != nil:
		return e.runCopy(ctx, client, step.Copy)
	case step.Ensure != nil:
		return e.runEnsure(ctx, client, step.Ensure, useSudo)
	case step.Template != nil:
		return e.runTemplate(ctx, client, step.Template, useSudo)
	default:
		return StepResult{
			Status: StatusFailed,
			Err:    fmt.Errorf("unknown step type"),
		}
	}
}

// runShell 在远程主机上执行单条 shell 命令。
func (e *Engine) runShell(ctx context.Context, client *ssh.Client, cmd string, sudo bool) StepResult {
	var (
		out string
		err error
	)
	if sudo {
		out, err = client.RunWithSudo(ctx, cmd)
	} else {
		out, err = client.Run(ctx, cmd)
	}

	if err != nil {
		return StepResult{Status: StatusFailed, Output: out, Err: err}
	}
	return StepResult{Status: StatusChanged, Output: out}
}

// runScript 将本地脚本文件内容上传并在远程执行。
func (e *Engine) runScript(ctx context.Context, client *ssh.Client, scriptPath string, sudo bool) StepResult {
	content, err := os.ReadFile(scriptPath)
	if err != nil {
		return StepResult{
			Status: StatusFailed,
			Err:    fmt.Errorf("read script %q: %w", scriptPath, err),
		}
	}

	var (
		out string
	)
	if sudo {
		out, err = client.RunScriptWithSudo(ctx, string(content))
	} else {
		out, err = client.RunScript(ctx, string(content))
	}

	if err != nil {
		return StepResult{Status: StatusFailed, Output: out, Err: err}
	}
	return StepResult{Status: StatusChanged, Output: out}
}

// runCopy 将本地文件上传到远程主机。
func (e *Engine) runCopy(ctx context.Context, client *ssh.Client, spec *CopySpec) StepResult {
	sftpCli, err := sftp.NewClient(client, sftp.WithForce(true))
	if err != nil {
		return StepResult{
			Status: StatusFailed,
			Err:    fmt.Errorf("create sftp client: %w", err),
		}
	}
	defer func() { _ = sftpCli.Close() }()

	if err := sftpCli.Upload(ctx, spec.Src, spec.Dest, nil); err != nil {
		return StepResult{
			Status: StatusFailed,
			Err:    fmt.Errorf("upload %q -> %q: %w", spec.Src, spec.Dest, err),
		}
	}

	// 如果指定了文件权限，chmod 远程文件
	if spec.Mode != "" {
		if err := applyRemoteMode(sftpCli, spec.Dest, spec.Mode); err != nil {
			return StepResult{
				Status: StatusFailed,
				Err:    fmt.Errorf("chmod %q: %w", spec.Dest, err),
			}
		}
	}

	return StepResult{Status: StatusChanged}
}

// applyRemoteMode 对远程文件设置权限。
func applyRemoteMode(c *sftp.Client, remotePath, mode string) error {
	perm, err := strconv.ParseUint(mode, 8, 32)
	if err != nil {
		return fmt.Errorf("invalid mode %q: %w", mode, err)
	}
	return c.SFTPClient().Chmod(remotePath, os.FileMode(perm))
}

// runEnsure 执行幂等性状态收敛：先 check，不满足时执行 action，再验证。
//
// 状态机：
//   - check 通过 (exit 0) → StatusSkipped（已满足，无需变更）
//   - check 未通过 → 执行 action → 再次 check
//   - 再次 check 通过 → StatusChanged（执行了修复）
//   - 再次 check 未通过 → StatusFailed（修复后仍不满足）
func (e *Engine) runEnsure(ctx context.Context, client *ssh.Client, spec *EnsureSpec, sudo bool) StepResult {
	// 第一次检查
	checkFn := func() (string, error) {
		if sudo {
			return client.RunWithSudo(ctx, spec.Check)
		}
		return client.Run(ctx, spec.Check)
	}

	_, checkErr := checkFn()
	if checkErr == nil {
		// 已满足，跳过
		return StepResult{Status: StatusSkipped, Output: "check passed, no action needed"}
	}

	// 执行修复 action
	var (
		actionOut string
		actionErr error
	)
	if sudo {
		actionOut, actionErr = client.RunWithSudo(ctx, spec.Action)
	} else {
		actionOut, actionErr = client.Run(ctx, spec.Action)
	}

	if actionErr != nil {
		return StepResult{
			Status: StatusFailed,
			Output: actionOut,
			Err:    fmt.Errorf("action failed: %w", actionErr),
		}
	}

	// 修复后再次验证
	_, verifyErr := checkFn()
	if verifyErr != nil {
		return StepResult{
			Status: StatusFailed,
			Output: actionOut,
			Err:    fmt.Errorf("post-action check still failed: %w", verifyErr),
		}
	}

	return StepResult{Status: StatusChanged, Output: actionOut}
}

// runTemplate 将本地 Go 模板文件渲染后上传到远程主机。
func (e *Engine) runTemplate(ctx context.Context, client *ssh.Client, spec *CopySpec, _ bool) StepResult {
	srcData, err := os.ReadFile(spec.Src)
	if err != nil {
		return StepResult{
			Status: StatusFailed,
			Err:    fmt.Errorf("read template %q: %w", spec.Src, err),
		}
	}

	tmpl, err := template.New("").Option("missingkey=error").Parse(string(srcData))
	if err != nil {
		return StepResult{
			Status: StatusFailed,
			Err:    fmt.Errorf("parse template %q: %w", spec.Src, err),
		}
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, e.pb.Vars); err != nil {
		return StepResult{
			Status: StatusFailed,
			Err:    fmt.Errorf("render template %q: %w", spec.Src, err),
		}
	}

	// 将渲染结果写入临时文件，再通过 SFTP 上传
	tmpFile, err := os.CreateTemp("", "xops-tmpl-*")
	if err != nil {
		return StepResult{
			Status: StatusFailed,
			Err:    fmt.Errorf("create temp file: %w", err),
		}
	}
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
	}()

	if _, err := tmpFile.Write(buf.Bytes()); err != nil {
		return StepResult{
			Status: StatusFailed,
			Err:    fmt.Errorf("write temp file: %w", err),
		}
	}
	_ = tmpFile.Close()

	// 复用 runCopy 完成上传
	return e.runCopy(ctx, client, &CopySpec{
		Src:  tmpFile.Name(),
		Dest: spec.Dest,
		Mode: spec.Mode,
	})
}
