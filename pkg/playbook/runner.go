package playbook

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	pkgsftp "github.com/pkg/sftp"
	cryptoSSH "golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/sftp"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
)

// runStep 根据步骤类型分发到对应执行器，并处理重试逻辑。
func (e *Engine) runStep(ctx context.Context, client *ssh.Client, step Step, globalSudo bool, node models.Node) StepResult {
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
		result = e.dispatchStepFn(ctx, client, step, useSudo, node)
		result.StepName = step.Name
		result.Duration = time.Since(start)

		if result.Status != StatusFailed {
			return result
		}

		// 不确定结果、未启动失败及附加清理错误禁止重试
		if !result.Retryable || result.Outcome != ssh.ExecutionCompleted || result.CleanupErr != nil || result.IOErr != nil {
			return result
		}

		if attempt < step.Retries {
			// 等待后重试
			select {
			case <-ctx.Done():
				result.Err = ctx.Err()
				result.Outcome = ssh.ExecutionUnknown
				result.Retryable = false
				return result
			case <-time.After(retryDelay):
			}
		}
	}

	return result
}

// dispatchStep 将步骤分发到对应的执行函数。
func (e *Engine) dispatchStep(ctx context.Context, client *ssh.Client, step Step, useSudo bool, node models.Node) StepResult {
	switch {
	case step.Shell != "":
		return e.runShell(ctx, client, step.Shell, step.Execution, useSudo, node)
	case step.Script != "":
		return e.runScript(ctx, client, step.Script, step.Execution, useSudo, node)
	case step.Copy != nil:
		return e.runCopy(ctx, client, step.Copy)
	case step.Ensure != nil:
		return e.runEnsure(ctx, client, step.Ensure, step.Execution, useSudo, node)
	case step.Template != nil:
		return e.runTemplate(ctx, client, step.Template, useSudo)
	default:
		return StepResult{
			Status:    StatusFailed,
			Outcome:   ssh.ExecutionNotStarted,
			Retryable: false,
			Err:       fmt.Errorf("unknown step type"),
		}
	}
}

func (e *Engine) globalExecution() *ssh.ExecutionConfig {
	if e == nil {
		return nil
	}
	if e.globalExecCaptured {
		return e.frozenGlobalExec
	}
	if e.provider == nil {
		return nil
	}
	snap := e.provider.Snapshot()
	if snap == nil {
		return nil
	}
	return snap.Execution
}

func hasJoinedDescendants(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := err.(interface{ Unwrap() []error }); ok {
		return true
	}
	if single, ok := err.(interface{ Unwrap() error }); ok {
		return hasJoinedDescendants(single.Unwrap())
	}
	return false
}

func unwrapJoinedErrors(err error) []error {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var res []error
		for _, child := range joined.Unwrap() {
			res = append(res, unwrapJoinedErrors(child)...)
		}
		return res
	}
	if single, ok := err.(interface{ Unwrap() error }); ok {
		child := single.Unwrap()
		if child != nil && hasJoinedDescendants(child) {
			return unwrapJoinedErrors(child)
		}
	}
	return []error{err}
}

func extractExecutionLayerError(err error) error {
	if err == nil {
		return nil
	}
	leaves := unwrapJoinedErrors(err)
	var execErrs []error
	for _, leaf := range leaves {
		if leaf == nil {
			continue
		}
		var cmdExitErr *ssh.CommandExitError
		if errors.As(leaf, &cmdExitErr) {
			continue
		}
		var cryptoExitErr *cryptoSSH.ExitError
		if errors.As(leaf, &cryptoExitErr) {
			continue
		}
		execErrs = append(execErrs, leaf)
	}
	return errors.Join(execErrs...)
}

func isCleanupError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "close ") ||
		strings.Contains(msg, "closed") ||
		strings.Contains(msg, "close ssh") ||
		strings.Contains(msg, "shutdown") ||
		strings.Contains(msg, "interrupt") ||
		strings.Contains(msg, "cleanup")
}

func isIOError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "stdin") ||
		strings.Contains(msg, "stdout") ||
		strings.Contains(msg, "stderr") ||
		strings.Contains(msg, "output copy") ||
		strings.Contains(msg, "output write") ||
		strings.Contains(msg, "output failed") ||
		strings.Contains(msg, "flush") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "duplicate ssh command")
}

func classifySessionError(err error) (exitCode *uint32, signal string, hasExit bool, cleanupErr error, ioErr error, otherErr error, isCanceled bool) {
	if err == nil {
		return nil, "", false, nil, nil, nil, false
	}

	leaves := unwrapJoinedErrors(err)
	for _, leaf := range leaves {
		if leaf == nil {
			continue
		}
		var exitErr *cryptoSSH.ExitError
		if errors.As(leaf, &exitErr) {
			hasExit = true
			if s := exitErr.Signal(); s != "" {
				signal = s
				exitCode = nil
			} else {
				code := uint32(exitErr.ExitStatus())
				exitCode = &code
			}
			continue
		}
		if errors.Is(leaf, context.Canceled) || errors.Is(leaf, context.DeadlineExceeded) {
			isCanceled = true
			otherErr = errors.Join(otherErr, leaf)
			continue
		}
		if isCleanupError(leaf) {
			cleanupErr = errors.Join(cleanupErr, leaf)
			continue
		}
		if isIOError(leaf) {
			ioErr = errors.Join(ioErr, leaf)
			continue
		}
		otherErr = errors.Join(otherErr, leaf)
	}
	return exitCode, signal, hasExit, cleanupErr, ioErr, otherErr, isCanceled
}

func classifySessionResult(err error, out string) StepResult {
	ec, sig, hasExit, cleanupErr, ioErr, otherErr, isCanceled := classifySessionError(err)

	var outcome ssh.ExecutionOutcome
	switch {
	case isCanceled:
		outcome = ssh.ExecutionUnknown
	case hasExit && otherErr == nil:
		outcome = ssh.ExecutionCompleted
	default:
		outcome = ssh.ExecutionUnknown
	}

	retryable := outcome == ssh.ExecutionCompleted &&
		!isCanceled &&
		cleanupErr == nil &&
		ioErr == nil &&
		otherErr == nil &&
		sig == "" &&
		ec != nil && *ec != 0

	return StepResult{
		Status:     StatusFailed,
		Outcome:    outcome,
		ExitCode:   ec,
		Signal:     sig,
		Output:     out,
		Err:        err,
		CleanupErr: cleanupErr,
		IOErr:      ioErr,
		Retryable:  retryable,
	}
}

func parseExitError(err error) (*uint32, string, bool) {
	ec, sig, hasExit, _, _, _, _ := classifySessionError(err)
	return ec, sig, hasExit
}

// runShell 在远程主机上执行单条 shell 命令。
func (e *Engine) runShell(ctx context.Context, client *ssh.Client, cmd string, stepExec *ssh.ExecutionConfig, sudo bool, node models.Node) StepResult {
	globalExec := e.globalExecution()
	var settingsExec *ssh.ExecutionConfig
	if e.pb != nil {
		settingsExec = e.pb.Settings.Execution
	}
	effectiveExec, err := ssh.EffectiveExecution(stepExec, settingsExec, node.Execution, globalExec)
	if err != nil {
		return StepResult{
			Status:    StatusFailed,
			Outcome:   ssh.ExecutionNotStarted,
			Retryable: false,
			Err:       err,
		}
	}

	if effectiveExec != nil {
		return e.runShellEffective(ctx, client, cmd, effectiveExec, sudo)
	}
	return e.runShellLegacy(ctx, client, cmd, sudo)
}

func (e *Engine) runShellEffective(ctx context.Context, client *ssh.Client, cmd string, effectiveExec *ssh.ExecutionConfig, sudo bool) StepResult {
	if sudo {
		out, sudoErr := client.RunWithSudoExecution(ctx, cmd, effectiveExec)
		if sudoErr != nil {
			if errors.Is(sudoErr, ssh.ErrExecutionValidation) {
				return StepResult{Status: StatusFailed, Outcome: ssh.ExecutionNotStarted, Err: sudoErr}
			}
			return classifySessionResult(sudoErr, out)
		}
		zero := uint32(0)
		return StepResult{
			Status:    StatusChanged,
			Outcome:   ssh.ExecutionCompleted,
			ExitCode:  &zero,
			Output:    out,
			Retryable: false,
		}
	}

	plan, planErr := ssh.PlanCommand(cmd, effectiveExec.CommandOptions())
	if planErr != nil {
		return StepResult{
			Status:    StatusFailed,
			Outcome:   ssh.ExecutionNotStarted,
			Retryable: false,
			Err:       planErr,
		}
	}

	cmdRes := client.ExecuteCommand(ctx, plan)
	execErr := extractExecutionLayerError(cmdRes.ExecutionErr)
	outcome := cmdRes.Outcome
	if errors.Is(execErr, context.Canceled) || errors.Is(execErr, context.DeadlineExceeded) {
		outcome = ssh.ExecutionUnknown
	}
	retryable := outcome == ssh.ExecutionCompleted &&
		execErr == nil &&
		cmdRes.CleanupErr == nil &&
		cmdRes.IOErr == nil &&
		cmdRes.Signal == "" &&
		cmdRes.ExitCode != nil && *cmdRes.ExitCode != 0
	status := StatusChanged
	if cmdRes.Err() != nil || (cmdRes.ExitCode != nil && *cmdRes.ExitCode != 0) {
		status = StatusFailed
	}
	return StepResult{
		Status:     status,
		Outcome:    outcome,
		ExitCode:   cmdRes.ExitCode,
		Signal:     cmdRes.Signal,
		PlanDigest: cmdRes.PlanDigest,
		Output:     cmdRes.Output,
		Truncated:  cmdRes.Truncated,
		Err:        cmdRes.Err(),
		CleanupErr: cmdRes.CleanupErr,
		IOErr:      cmdRes.IOErr,
		Retryable:  retryable,
	}
}

func (e *Engine) runShellLegacy(ctx context.Context, client *ssh.Client, cmd string, sudo bool) StepResult {
	var (
		out      string
		shellErr error
	)
	if sudo {
		out, shellErr = client.RunWithSudo(ctx, cmd)
	} else {
		out, shellErr = client.Run(ctx, cmd)
	}

	if shellErr != nil {
		return classifySessionResult(shellErr, out)
	}
	zero := uint32(0)
	return StepResult{
		Status:    StatusChanged,
		Outcome:   ssh.ExecutionCompleted,
		ExitCode:  &zero,
		Output:    out,
		Retryable: false,
	}
}

// runScript 将本地脚本文件内容并在远程执行。
func (e *Engine) runScript(ctx context.Context, client *ssh.Client, scriptPath string, stepExec *ssh.ExecutionConfig, sudo bool, node models.Node) StepResult {
	var content []byte
	if e != nil && e.scriptSources != nil {
		content = e.scriptSources[scriptPath]
	}
	if content == nil {
		var err error
		content, err = os.ReadFile(scriptPath)
		if err != nil {
			return StepResult{
				Status:    StatusFailed,
				Outcome:   ssh.ExecutionNotStarted,
				Retryable: false,
				Err:       fmt.Errorf("read script %q: %w", scriptPath, err),
			}
		}
	}

	globalExec := e.globalExecution()
	var settingsExec *ssh.ExecutionConfig
	if e.pb != nil {
		settingsExec = e.pb.Settings.Execution
	}

	resolvedExec, err := ssh.ResolveScriptExecution(stepExec, settingsExec, node.Execution, globalExec, content)
	if err != nil {
		return StepResult{
			Status:    StatusFailed,
			Outcome:   ssh.ExecutionNotStarted,
			Retryable: false,
			Err:       fmt.Errorf("resolve script execution for %q: %w", scriptPath, err),
		}
	}

	var opts []ssh.RunOption
	if resolvedExec != nil && resolvedExec.Login != nil {
		opts = append(opts, ssh.WithLoginShell(*resolvedExec.Login))
	}

	var (
		out       string
		scriptErr error
	)
	if sudo {
		out, scriptErr = client.RunScriptWithSudoExecution(ctx, string(content), resolvedExec)
	} else {
		out, scriptErr = client.RunScript(ctx, string(content), opts...)
	}

	if scriptErr != nil {
		if errors.Is(scriptErr, ssh.ErrExecutionValidation) {
			return StepResult{Status: StatusFailed, Outcome: ssh.ExecutionNotStarted, Err: scriptErr}
		}
		return classifySessionResult(scriptErr, out)
	}

	zero := uint32(0)
	return StepResult{
		Status:    StatusChanged,
		Outcome:   ssh.ExecutionCompleted,
		ExitCode:  &zero,
		Output:    out,
		Retryable: false,
	}
}

// runCopy 将本地文件上传到远程主机。
func (e *Engine) runCopy(ctx context.Context, client *ssh.Client, spec *CopySpec) (result StepResult) {
	sftpCli, err := sftp.NewClient(ctx, client, sftp.WithForce(true))
	if err != nil {
		return StepResult{
			Status:    StatusFailed,
			Outcome:   ssh.ExecutionNotStarted,
			Retryable: false,
			Err:       fmt.Errorf("create sftp client: %w", err),
		}
	}
	defer func() {
		if closeErr := sftpCli.Close(); closeErr != nil {
			result = failStepResult(result, fmt.Errorf("close sftp client: %w", closeErr))
		}
	}()

	if err := sftpCli.Upload(ctx, spec.Src, spec.Dest, nil); err != nil {
		return StepResult{
			Status:    StatusFailed,
			Outcome:   ssh.ExecutionUnknown,
			Retryable: false,
			Err:       fmt.Errorf("upload %q -> %q: %w", spec.Src, spec.Dest, err),
		}
	}

	// 如果指定了文件权限，chmod 远程文件
	if spec.Mode != "" {
		if err := applyRemoteMode(ctx, sftpCli, spec.Dest, spec.Mode); err != nil {
			return StepResult{
				Status:    StatusFailed,
				Outcome:   ssh.ExecutionUnknown,
				Retryable: false,
				Err:       fmt.Errorf("chmod %q: %w", spec.Dest, err),
			}
		}
	}

	return StepResult{Status: StatusChanged, Outcome: ssh.ExecutionCompleted, Retryable: false}
}

// applyRemoteMode 对远程文件设置权限。
func applyRemoteMode(ctx context.Context, c *sftp.Client, remotePath, mode string) error {
	perm, err := strconv.ParseUint(mode, 8, 32)
	if err != nil {
		return fmt.Errorf("invalid mode %q: %w", mode, err)
	}
	return c.Do(ctx, func(client *pkgsftp.Client) error {
		return client.Chmod(remotePath, os.FileMode(perm))
	})
}

func generateEnsureNonce() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func extractEnsureFrame(output, marker string) (string, uint32, bool) {
	tag := marker + ":"
	idx := strings.LastIndex(output, tag)
	if idx < 0 {
		return output, 0, false
	}
	rest := output[idx+len(tag):]
	endLine := strings.IndexByte(rest, '\n')
	var codeStr string
	if endLine < 0 {
		codeStr = rest
	} else {
		codeStr = rest[:endLine]
	}
	codeStr = strings.TrimSpace(codeStr)
	parsed, err := strconv.ParseUint(codeStr, 10, 32)
	if err != nil {
		return output, 0, false
	}

	// Remove the frame line from output
	before := strings.TrimRight(output[:idx], "\r\n")
	var after string
	if endLine >= 0 && endLine+1 < len(rest) {
		after = strings.TrimLeft(rest[endLine+1:], "\r\n")
	}
	clean := before
	if after != "" {
		if clean != "" {
			clean += "\n" + after
		} else {
			clean = after
		}
	}
	return clean, uint32(parsed), true
}

func (e *Engine) executeEnsureCheck(ctx context.Context, client *ssh.Client, checkCmd string, stepExec *ssh.ExecutionConfig, sudo bool, node models.Node) (string, uint32, StepResult) {
	globalExec := e.globalExecution()
	var settingsExec *ssh.ExecutionConfig
	if e.pb != nil {
		settingsExec = e.pb.Settings.Execution
	}
	effectiveExec, err := ssh.EffectiveExecution(stepExec, settingsExec, node.Execution, globalExec)
	if err != nil {
		return "", 0, StepResult{
			Status:    StatusFailed,
			Outcome:   ssh.ExecutionNotStarted,
			Retryable: false,
			Err:       err,
		}
	}

	if effectiveExec != nil && effectiveExec.Interpreter == ssh.InterpreterServer {
		return "", 0, StepResult{
			Status:    StatusFailed,
			Outcome:   ssh.ExecutionNotStarted,
			Retryable: false,
			Err:       fmt.Errorf("ensure check unsupported with server interpreter: cannot verify check result origin without controlled shell adapter"),
		}
	}

	marker := fmt.Sprintf("__XOPS_ENSURE_%s__", generateEnsureNonce())
	wrappedCheck := fmt.Sprintf("{\n  trap 'printf \"\\n%s:%%d\\n\" \"$?\"' EXIT\n  %s\n}", marker, checkCmd)

	if effectiveExec != nil {
		if sudo {
			return e.executeEnsureCheckSudo(ctx, client, wrappedCheck, marker, effectiveExec)
		}
		return e.executeEnsureCheckPlanned(ctx, client, wrappedCheck, marker, effectiveExec)
	}
	return e.executeEnsureCheckLegacy(ctx, client, wrappedCheck, marker, sudo)
}

func (e *Engine) executeEnsureCheckSudo(ctx context.Context, client *ssh.Client, wrappedCheck, marker string, effectiveExec *ssh.ExecutionConfig) (string, uint32, StepResult) {
	out, sudoErr := client.RunWithSudoExecution(ctx, wrappedCheck, effectiveExec)
	if sudoErr != nil {
		if errors.Is(sudoErr, ssh.ErrExecutionValidation) {
			return "", 0, StepResult{Status: StatusFailed, Outcome: ssh.ExecutionNotStarted, Err: sudoErr}
		}
		ec, sig, hasExit, cleanupErr, ioErr, otherErr, isCanceled := classifySessionError(sudoErr)
		if isCanceled || otherErr != nil || !hasExit {
			return "", 0, StepResult{
				Status:    StatusFailed,
				Outcome:   ssh.ExecutionUnknown,
				Output:    out,
				Err:       fmt.Errorf("ensure check execution failed: %w", sudoErr),
				Retryable: false,
			}
		}
		if cleanupErr != nil || ioErr != nil {
			cleanOut, _, _ := extractEnsureFrame(out, marker)
			return cleanOut, 0, StepResult{
				Status:     StatusFailed,
				Outcome:    ssh.ExecutionCompleted,
				ExitCode:   ec,
				Signal:     sig,
				CleanupErr: cleanupErr,
				IOErr:      ioErr,
				Output:     cleanOut,
				Err:        fmt.Errorf("ensure check had I/O or cleanup error: %w", sudoErr),
				Retryable:  false,
			}
		}
		if sig != "" {
			cleanOut, _, _ := extractEnsureFrame(out, marker)
			return cleanOut, 0, StepResult{
				Status:    StatusFailed,
				Outcome:   ssh.ExecutionCompleted,
				Signal:    sig,
				Output:    cleanOut,
				Err:       fmt.Errorf("ensure check terminated by signal %s", sig),
				Retryable: false,
			}
		}
	}
	cleanOut, code, ok := extractEnsureFrame(out, marker)
	if !ok {
		ec, sig, _ := parseExitError(sudoErr)
		return cleanOut, 0, StepResult{
			Status:    StatusFailed,
			Outcome:   ssh.ExecutionCompleted,
			ExitCode:  ec,
			Signal:    sig,
			Output:    cleanOut,
			Err:       fmt.Errorf("ensure check result frame missing (check was not reached or exited prematurely), action not executed"),
			Retryable: false,
		}
	}
	return cleanOut, code, StepResult{Status: StatusOK, Outcome: ssh.ExecutionCompleted, Output: cleanOut}
}

func (e *Engine) executeEnsureCheckPlanned(ctx context.Context, client *ssh.Client, wrappedCheck, marker string, effectiveExec *ssh.ExecutionConfig) (string, uint32, StepResult) {
	plan, planErr := ssh.PlanCommand(wrappedCheck, effectiveExec.CommandOptions())
	if planErr != nil {
		return "", 0, StepResult{
			Status:    StatusFailed,
			Outcome:   ssh.ExecutionNotStarted,
			Retryable: false,
			Err:       planErr,
		}
	}
	cmdRes := client.ExecuteCommand(ctx, plan)
	if cmdRes.Outcome != ssh.ExecutionCompleted {
		cleanOut, _, _ := extractEnsureFrame(cmdRes.Output, marker)
		return cleanOut, 0, StepResult{
			Status:    StatusFailed,
			Outcome:   cmdRes.Outcome,
			Output:    cleanOut,
			Err:       fmt.Errorf("ensure check failed or timed out: %w", cmdRes.Err()),
			Retryable: false,
		}
	}
	if execErr := extractExecutionLayerError(cmdRes.ExecutionErr); execErr != nil {
		cleanOut, _, _ := extractEnsureFrame(cmdRes.Output, marker)
		outcome := cmdRes.Outcome
		if errors.Is(execErr, context.Canceled) || errors.Is(execErr, context.DeadlineExceeded) {
			outcome = ssh.ExecutionUnknown
		}
		return cleanOut, 0, StepResult{
			Status:    StatusFailed,
			Outcome:   outcome,
			Output:    cleanOut,
			Err:       fmt.Errorf("ensure check failed or timed out: %w", execErr),
			Retryable: false,
		}
	}
	if cmdRes.CleanupErr != nil || cmdRes.IOErr != nil {
		cleanOut, _, _ := extractEnsureFrame(cmdRes.Output, marker)
		return cleanOut, 0, StepResult{
			Status:     StatusFailed,
			Outcome:    cmdRes.Outcome,
			Output:     cleanOut,
			CleanupErr: cmdRes.CleanupErr,
			IOErr:      cmdRes.IOErr,
			Err:        fmt.Errorf("ensure check had I/O or cleanup error: %w", cmdRes.Err()),
			Retryable:  false,
		}
	}
	cleanOut, code, ok := extractEnsureFrame(cmdRes.Output, marker)
	if cmdRes.Signal != "" {
		return cleanOut, 0, StepResult{
			Status:    StatusFailed,
			Outcome:   ssh.ExecutionCompleted,
			Signal:    cmdRes.Signal,
			Output:    cleanOut,
			Err:       fmt.Errorf("ensure check terminated by signal %s", cmdRes.Signal),
			Retryable: false,
		}
	}
	if !ok {
		return cleanOut, 0, StepResult{
			Status:    StatusFailed,
			Outcome:   ssh.ExecutionCompleted,
			ExitCode:  cmdRes.ExitCode,
			Signal:    cmdRes.Signal,
			Output:    cleanOut,
			Err:       fmt.Errorf("ensure check result frame missing (check was not reached or exited prematurely), action not executed"),
			Retryable: false,
		}
	}
	return cleanOut, code, StepResult{Status: StatusOK, Outcome: ssh.ExecutionCompleted, Output: cleanOut}
}

func (e *Engine) executeEnsureCheckLegacy(ctx context.Context, client *ssh.Client, wrappedCheck, marker string, sudo bool) (string, uint32, StepResult) {
	var (
		out      string
		checkErr error
	)
	if sudo {
		out, checkErr = client.RunWithSudo(ctx, wrappedCheck)
	} else {
		out, checkErr = client.Run(ctx, wrappedCheck)
	}
	if checkErr != nil {
		ec, sig, hasExit, cleanupErr, ioErr, otherErr, isCanceled := classifySessionError(checkErr)
		if isCanceled || otherErr != nil || !hasExit {
			return "", 0, StepResult{
				Status:    StatusFailed,
				Outcome:   ssh.ExecutionUnknown,
				Output:    out,
				Err:       fmt.Errorf("ensure check execution failed: %w", checkErr),
				Retryable: false,
			}
		}
		if cleanupErr != nil || ioErr != nil {
			cleanOut, _, _ := extractEnsureFrame(out, marker)
			return cleanOut, 0, StepResult{
				Status:     StatusFailed,
				Outcome:    ssh.ExecutionCompleted,
				ExitCode:   ec,
				Signal:     sig,
				CleanupErr: cleanupErr,
				IOErr:      ioErr,
				Output:     cleanOut,
				Err:        fmt.Errorf("ensure check had I/O or cleanup error: %w", checkErr),
				Retryable:  false,
			}
		}
		if sig != "" {
			cleanOut, _, _ := extractEnsureFrame(out, marker)
			return cleanOut, 0, StepResult{
				Status:    StatusFailed,
				Outcome:   ssh.ExecutionCompleted,
				Signal:    sig,
				Output:    cleanOut,
				Err:       fmt.Errorf("ensure check terminated by signal %s", sig),
				Retryable: false,
			}
		}
	}
	cleanOut, code, ok := extractEnsureFrame(out, marker)
	if !ok {
		ec, sig, _ := parseExitError(checkErr)
		return cleanOut, 0, StepResult{
			Status:    StatusFailed,
			Outcome:   ssh.ExecutionCompleted,
			ExitCode:  ec,
			Signal:    sig,
			Output:    cleanOut,
			Err:       fmt.Errorf("ensure check result frame missing (check was not reached or exited prematurely), action not executed"),
			Retryable: false,
		}
	}
	return cleanOut, code, StepResult{Status: StatusOK, Outcome: ssh.ExecutionCompleted, Output: cleanOut}
}

// runEnsure 执行幂等性状态收敛：先 check，确认不满足时执行 action，再验证。
//
// 结果协议：
//   - check 通过 (exit 0) → StatusSkipped（已满足，无需变更）
//   - check 退出码 127、超时、断连或执行层故障/缺少结果帧 → StatusFailed（停止，严禁执行 action）
//   - check 确认非 0（排除 127）且具备有效结果帧 → 执行 action → 再次 check 验证
//   - 再次 check 通过 (exit 0) → StatusChanged（修复成功）
//   - 再次 check 失败 → StatusFailed（修复后仍不满足）
func (e *Engine) runEnsure(ctx context.Context, client *ssh.Client, spec *EnsureSpec, stepExec *ssh.ExecutionConfig, sudo bool, node models.Node) StepResult {
	cleanOut, checkCode, checkRes := e.executeEnsureCheck(ctx, client, spec.Check, stepExec, sudo, node)
	if checkRes.Status == StatusFailed {
		return checkRes
	}

	if checkCode == 0 {
		return StepResult{
			Status:    StatusSkipped,
			Outcome:   ssh.ExecutionCompleted,
			Output:    "check passed, no action needed",
			Retryable: false,
		}
	}

	if checkCode == 127 {
		return StepResult{
			Status:    StatusFailed,
			Outcome:   ssh.ExecutionCompleted,
			Output:    cleanOut,
			Err:       fmt.Errorf("ensure check exited with 127 (cannot distinguish command missing from startup failure), action not executed"),
			Retryable: false,
		}
	}

	// 确认不满足：执行 action
	actionRes := e.runShell(ctx, client, spec.Action, stepExec, sudo, node)
	if actionRes.Status == StatusFailed {
		actionRes.Err = fmt.Errorf("action failed: %w", actionRes.Err)
		return actionRes
	}

	// 验证阶段 (verify check)
	verifyOut, verifyCode, verifyRes := e.executeEnsureCheck(ctx, client, spec.Check, stepExec, sudo, node)
	if verifyRes.Status == StatusFailed {
		return StepResult{
			Status:    StatusFailed,
			Outcome:   verifyRes.Outcome,
			ExitCode:  verifyRes.ExitCode,
			Signal:    verifyRes.Signal,
			Output:    actionRes.Output,
			Err:       fmt.Errorf("post-action verify check failed: %w", verifyRes.Err),
			Retryable: false,
		}
	}

	if verifyCode == 0 {
		return StepResult{
			Status:    StatusChanged,
			Outcome:   ssh.ExecutionCompleted,
			Output:    actionRes.Output,
			Retryable: false,
		}
	}

	return StepResult{
		Status:    StatusFailed,
		Outcome:   ssh.ExecutionCompleted,
		Output:    actionRes.Output,
		Err:       fmt.Errorf("post-action verify check still not satisfied (exit code %d): %s", verifyCode, verifyOut),
		Retryable: false,
	}
}

// runTemplate 将本地 Go 模板文件渲染后上传到远程主机。
func (e *Engine) runTemplate(ctx context.Context, client *ssh.Client, spec *CopySpec, _ bool) (result StepResult) {
	srcData, err := os.ReadFile(spec.Src)
	if err != nil {
		return StepResult{
			Status:    StatusFailed,
			Outcome:   ssh.ExecutionNotStarted,
			Retryable: false,
			Err:       fmt.Errorf("read template %q: %w", spec.Src, err),
		}
	}

	tmpl, err := template.New("").Option("missingkey=error").Parse(string(srcData))
	if err != nil {
		return StepResult{
			Status:    StatusFailed,
			Outcome:   ssh.ExecutionNotStarted,
			Retryable: false,
			Err:       fmt.Errorf("parse template %q: %w", spec.Src, err),
		}
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, e.pb.Vars); err != nil {
		return StepResult{
			Status:    StatusFailed,
			Outcome:   ssh.ExecutionNotStarted,
			Retryable: false,
			Err:       fmt.Errorf("render template %q: %w", spec.Src, err),
		}
	}

	// 将渲染结果写入临时文件，再通过 SFTP 上传
	tmpFile, err := os.CreateTemp("", "xops-tmpl-*")
	if err != nil {
		return StepResult{
			Status:    StatusFailed,
			Outcome:   ssh.ExecutionNotStarted,
			Retryable: false,
			Err:       fmt.Errorf("create temp file: %w", err),
		}
	}
	tmpFileOpen := true
	defer func() {
		if tmpFileOpen {
			if closeErr := tmpFile.Close(); closeErr != nil {
				result = failStepResult(result, fmt.Errorf("close temp file: %w", closeErr))
			}
		}
		if removeErr := os.Remove(tmpFile.Name()); removeErr != nil {
			result = failStepResult(result, fmt.Errorf("remove temp file: %w", removeErr))
		}
	}()

	if _, err := tmpFile.Write(buf.Bytes()); err != nil {
		return StepResult{
			Status:    StatusFailed,
			Outcome:   ssh.ExecutionNotStarted,
			Retryable: false,
			Err:       fmt.Errorf("write temp file: %w", err),
		}
	}
	if err := tmpFile.Close(); err != nil {
		tmpFileOpen = false
		return StepResult{
			Status:    StatusFailed,
			Outcome:   ssh.ExecutionNotStarted,
			Retryable: false,
			Err:       fmt.Errorf("close temp file: %w", err),
		}
	}
	tmpFileOpen = false

	// 复用 runCopy 完成上传
	return e.runCopy(ctx, client, &CopySpec{
		Src:  tmpFile.Name(),
		Dest: spec.Dest,
		Mode: spec.Mode,
	})
}

func failStepResult(result StepResult, err error) StepResult {
	if err == nil {
		return result
	}
	result.Status = StatusFailed
	result.CleanupErr = errors.Join(result.CleanupErr, err)
	result.Err = errors.Join(result.Err, err)
	result.Retryable = false
	return result
}
