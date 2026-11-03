package credentialhelper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/wentf9/xops-cli/pkg/credential"
)

// DefaultAnswerCommandTimeout 是外部答案获取命令执行的默认超时时间（15 秒）。
const DefaultAnswerCommandTimeout = 15 * time.Second

// MaxAnswerStdoutBytes 是外部答案命令允许读取的最大 stdout 字节数（4096 字节）。
const MaxAnswerStdoutBytes = 4096

// AnswerCommandOptions 包含执行外部答案命令所需的调用参数与上下文注入参数。
type AnswerCommandOptions struct {
	// Command 是要执行的可执行文件绝对路径或名称（直接调用，绝不通过 shell 包装）。
	Command string
	// Args 是传递给可执行文件的参数列表。
	Args []string
	// Timeout 是命令执行的超时时间，若 <= 0 则使用默认超时 DefaultAnswerCommandTimeout (15s)。
	Timeout time.Duration
	// Env 是可选的额外环境变量。
	Env []string

	// 上下文信息，将注入为只读的 XOPS_* 环境变量：
	// Node 是目标节点标识/名称，对应 XOPS_NODE。
	Node string
	// Host 是目标主机地址，对应 XOPS_HOST。
	Host string
	// User 是 SSH 登录用户名，对应 XOPS_USER。
	User string
	// Identity 是身份配置名称，对应 XOPS_IDENTITY。
	Identity string
	// Prompt 是服务端提示/问题文本（清洗控制字符后注入），对应 XOPS_PROMPT。
	Prompt string
	// Instruction 是服务端指令/描述文本（清洗控制字符后注入），对应 XOPS_INSTRUCTION。
	Instruction string
	// Echo 标识用户输入是否在终端回显，对应 XOPS_ECHO ("true" 或 "false")。
	Echo bool
	// NonInteractive 显式声明是否处于非交互模式，对应 XOPS_NON_INTERACTIVE ("1" 或 "0")。
	NonInteractive bool
}

var (
	promptAnsiCSIRegex = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
	promptAnsiOSCRegex = regexp.MustCompile(`\x1b\][^\x07\x1b]*(\x07|\x1b\\)`)
	promptAnsiEscRegex = regexp.MustCompile(`\x1b[@-Z\\-_]`)
)

// sanitizePromptEnv 清洗 prompt 与 instruction 文本中的 ANSI 转义序列及不可见控制字符，
// 保留换行符 (\n) 与制表符 (\t)。
func sanitizePromptEnv(raw string) string {
	if raw == "" {
		return ""
	}
	cleaned := promptAnsiCSIRegex.ReplaceAllString(raw, "")
	cleaned = promptAnsiOSCRegex.ReplaceAllString(cleaned, "")
	cleaned = promptAnsiEscRegex.ReplaceAllString(cleaned, "")

	var b strings.Builder
	b.Grow(len(cleaned))
	for _, r := range cleaned {
		if r == '\r' {
			continue
		}
		if r == '\n' || r == '\t' {
			b.WriteRune(r)
			continue
		}
		if unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// trimTrailingNewline 剥离末尾的单个换行符（\r\n、\n 或 \r），保留其他字符。
func trimTrailingNewline(data []byte) []byte {
	if bytes.HasSuffix(data, []byte("\r\n")) {
		return data[:len(data)-2]
	}
	if bytes.HasSuffix(data, []byte("\n")) {
		return data[:len(data)-1]
	}
	if bytes.HasSuffix(data, []byte("\r")) {
		return data[:len(data)-1]
	}
	return data
}

// RunAnswerCommand 执行外部答案命令，捕获其标准输出作为答案返回。
// 满足需求：
// 1. exec.CommandContext 直接执行，无 shell 包装；
// 2. 子进程 Stdin 绑定至 os.DevNull；
// 3. 注入只读 XOPS_* 环境变量；
// 4. 超时 (默认 15s) 或上下文取消时通过 KillTree 终止整个子进程树；
// 5. 限制 Stdout 最大读取 4096 字节 (io.LimitReader)，并排空剩余管道防止死锁，剥离末尾单个换行符；
// 6. 退出码非 0 时对 Stderr 进行敏感信息脱敏 (SanitizeDiagnostic) 后返回错误。
func RunAnswerCommand(ctx context.Context, opts AnswerCommandOptions) ([]byte, error) {
	if strings.TrimSpace(opts.Command) == "" {
		return nil, fmt.Errorf("answer command is empty")
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultAnswerCommandTimeout
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, opts.Command, opts.Args...)

	// 1. Stdin 绑定到 os.DevNull
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return nil, fmt.Errorf("open %s for stdin: %w", os.DevNull, err)
	}
	defer func() {
		_ = devNull.Close()
	}()
	cmd.Stdin = devNull

	// 2. 注入只读 XOPS_* 环境变量
	cmd.Env = buildAnswerEnv(ctx, opts)

	// 3. 设置 WaitDelay 防止孤儿孙进程阻塞管道排空
	waitDelay := DefaultProcessWaitDelay
	if timeout < waitDelay {
		waitDelay = timeout
	}
	cmd.WaitDelay = waitDelay

	// 4. Stdout 与 Stderr 设置缓冲限制器，由 os/exec 内部管理复制协程并在 Wait 中安全排空
	stdoutLimiter := &limitedBuffer{limit: MaxAnswerStdoutBytes}
	stderrLimiter := &limitedBuffer{limit: MaxStderrBytes}
	cmd.Stdout = stdoutLimiter
	cmd.Stderr = stderrLimiter

	session, err := startProcessSession(execCtx, cmd)
	if err != nil {
		if execCtx.Err() != nil {
			if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
				return nil, fmt.Errorf("answer command timed out after %v: %w", timeout, execCtx.Err())
			}
			return nil, fmt.Errorf("answer command canceled: %w", execCtx.Err())
		}
		if isNotFoundErr(err) {
			return nil, fmt.Errorf("answer command executable not found: %s", opts.Command)
		}
		return nil, fmt.Errorf("start answer command failed: %w", err)
	}
	defer func() {
		_ = session.Close()
	}()

	// 5. 监听上下文取消与超时，调用 session.KillTree() 终止进程树
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

	if execCtx.Err() != nil {
		_ = session.KillTree()
	}

	sanitizedStderr := SanitizeDiagnostic(stderrLimiter.buf.String())
	if err := handleAnswerRunError(execCtx, runErr, opts.Command, timeout, sanitizedStderr); err != nil {
		return nil, err
	}

	// 6. 剥离末尾换行符
	rawAnswer := trimTrailingNewline(stdoutLimiter.buf.Bytes())
	answer := make([]byte, len(rawAnswer))
	copy(answer, rawAnswer)
	return answer, nil
}

func buildAnswerEnv(ctx context.Context, opts AnswerCommandOptions) []string {
	env := make([]string, 0, len(os.Environ())+len(opts.Env)+8)
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "XOPS_") {
			env = append(env, e)
		}
	}
	for _, e := range opts.Env {
		if !strings.HasPrefix(e, "XOPS_") {
			env = append(env, e)
		}
	}

	nonInteractive := "0"
	if opts.NonInteractive || credential.InteractionDisabled(ctx) {
		nonInteractive = "1"
	}
	echoVal := "false"
	if opts.Echo {
		echoVal = "true"
	}

	return append(env,
		"XOPS_NODE="+opts.Node,
		"XOPS_HOST="+opts.Host,
		"XOPS_USER="+opts.User,
		"XOPS_IDENTITY="+opts.Identity,
		"XOPS_PROMPT="+sanitizePromptEnv(opts.Prompt),
		"XOPS_INSTRUCTION="+sanitizePromptEnv(opts.Instruction),
		"XOPS_ECHO="+echoVal,
		"XOPS_NON_INTERACTIVE="+nonInteractive,
	)
}

func handleAnswerRunError(execCtx context.Context, runErr error, command string, timeout time.Duration, sanitizedStderr string) error {
	if execCtx.Err() != nil {
		if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("answer command timed out after %v: %w", timeout, execCtx.Err())
		}
		return fmt.Errorf("answer command canceled: %w", execCtx.Err())
	}
	if runErr == nil || errors.Is(runErr, exec.ErrWaitDelay) {
		return nil
	}
	if isNotFoundErr(runErr) {
		return fmt.Errorf("answer command executable not found: %s", command)
	}
	if sanitizedStderr != "" {
		return fmt.Errorf("answer command failed (%w): %s", runErr, sanitizedStderr)
	}
	return fmt.Errorf("answer command failed: %w", runErr)
}
