package ssh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"sync"
	"time"
)

// DefaultPasswordPromptPattern 是内置的多语言密码提示正则，覆盖主流语言环境。
// 匹配规则：密码关键词后面可以跟其他单词（如 "for user"），之后出现冒号即触发。
const DefaultPasswordPromptPattern = `(?i)(password|mot de passe|passwort|kennwort|contraseña|パスワード|비밀번호|senha|пароль|密码)[^:：]*[:：]`

// ExpectRule 定义单条匹配规则：等待输出匹配 Pattern，然后调用 Respond 生成响应。
type ExpectRule struct {
	// Pattern 是用于匹配 PTY 输出的正则表达式。
	Pattern *regexp.Regexp

	// Respond 在 Pattern 命中后被调用，返回需要写入 stdin 的内容（不含换行符）。
	Respond func() (string, error)
}

// Expect 是一个被动的 io.Writer，拦截并分析 SSH 输出流，匹配多阶段交互。
// 通过实现 io.Writer，它消除了主动 Read 导致的 goroutine 泄露和数据竞争问题。
type Expect struct {
	mu            sync.Mutex
	rules         []ExpectRule
	ruleIdx       int
	outputBuf     bytes.Buffer
	writer        io.Writer // 用于自动回复的流（通常为 stdin）
	matched       chan struct{}
	stopped       bool
	accumulateAll bool      // 是否在匹配结束后继续累积输出到内部 Buffer
	Target        io.Writer // 匹配过程中和完成后的透传目标（用于交互式 Shell 实时显示）
	err           error     // 记录执行 Respond 时可能出现的错误
	matchOffset   int       // 记录已匹配内容的偏移量，避免截断缓冲导致历史丢失
}

// NewExpect 创建一个 Expect 实例。
// writer 是自动响应的目标（例如 SSH 会话的 stdin）。
func NewExpect(writer io.Writer, rules ...ExpectRule) *Expect {
	return &Expect{
		rules:   rules,
		writer:  writer,
		matched: make(chan struct{}),
	}
}

// SetTarget 设置透传目标，所有 Write 进来的数据都会原样写入 target。
func (e *Expect) SetTarget(target io.Writer) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Target = target
}

// SetAccumulate 设置是否在匹配结束后继续累积输出。
// 用于短生命周期的命令（如 runWithSu），以便执行完毕后获取完整输出。
func (e *Expect) SetAccumulate(acc bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.accumulateAll = acc
}

// Stop 停止匹配逻辑，释放资源，不再缓冲多余数据（除非 accumulateAll=true）。
func (e *Expect) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.stopped {
		e.stopped = true
		// 如果在未匹配完成时被强行停止，也应关闭 matched 通道以防止死锁
		select {
		case <-e.matched:
		default:
			close(e.matched)
		}
	}
}

// Write 实现了 io.Writer 接口，由 SSH 客户端底层主动调用，消除了竞态。
func (e *Expect) Write(p []byte) (n int, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.stopped && e.ruleIdx < len(e.rules) {
		e.outputBuf.Write(p)
		e.matchRulesLocked()
	} else if e.accumulateAll {
		e.outputBuf.Write(p)
	}

	if e.Target != nil {
		return e.Target.Write(p)
	}
	return len(p), nil
}

// matchRulesLocked 尝试在当前缓冲区匹配所有规则，必须在持有锁时调用。
func (e *Expect) matchRulesLocked() {
	for e.ruleIdx < len(e.rules) {
		current := e.rules[e.ruleIdx]
		loc := current.Pattern.FindIndex(e.outputBuf.Bytes()[e.matchOffset:])
		if loc == nil {
			break
		}

		if current.Respond != nil {
			response, err := current.Respond()
			if err != nil {
				e.err = fmt.Errorf("respond failed for pattern %s: %w", current.Pattern, err)
				e.stopped = true
				break
			}

			if _, err := fmt.Fprintf(e.writer, "%s\n", response); err != nil {
				e.err = fmt.Errorf("write response failed: %w", err)
				e.stopped = true
				break
			}
		}

		// 累加匹配偏移量，供下一条规则在剩余内容中继续匹配
		e.matchOffset += loc[1]
		e.ruleIdx++
	}

	// 所有规则均已匹配，或者发生错误时终止
	if e.ruleIdx == len(e.rules) || e.stopped {
		e.stopped = true
		select {
		case <-e.matched:
		default:
			close(e.matched)
		}
	}
}

// Wait 等待所有规则匹配完成、超时或 ctx 取消。
// 超时发生时，它会自动调用 Stop，后续不再进行任何正则匹配。
func (e *Expect) Wait(ctx context.Context, timeout time.Duration) error {
	if len(e.rules) == 0 {
		return nil
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case <-e.matched:
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.err
	case <-timeoutCtx.Done():
		e.Stop()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		e.mu.Lock()
		pattern := e.rules[e.ruleIdx].Pattern
		e.mu.Unlock()
		return fmt.Errorf("expect timeout after %s waiting for pattern: %s", timeout, pattern)
	}
}

// Output 返回内部缓冲区累积的所有输出。
func (e *Expect) Output() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.outputBuf.String()
}

// CleanOutput 返回清理后的输出：剔除匹配 promptPattern 的密码输入行。
func (e *Expect) CleanOutput(promptPattern *regexp.Regexp) string {
	raw := e.Output()
	if promptPattern == nil {
		return raw
	}
	var result []string
	for _, line := range bytes.Split([]byte(raw), []byte("\n")) {
		if !promptPattern.Match(line) && len(bytes.TrimSpace(line)) > 0 {
			result = append(result, string(line))
		}
	}
	return string(bytes.Join(func() [][]byte {
		b := make([][]byte, len(result))
		for i, s := range result {
			b[i] = []byte(s)
		}
		return b
	}(), []byte("\n")))
}

// StaticRespond 返回一个固定字符串的 Respond 回调。
func StaticRespond(s string) func() (string, error) {
	return func() (string, error) {
		return s, nil
	}
}
