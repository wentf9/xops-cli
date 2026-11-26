package interact

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
)

// StreamSpec 是构造基于自定义输入/输出流的确定性 Interaction 的显式入参规格（供 TCK 与单元测试使用）。
type StreamSpec struct {
	In          io.Reader
	Out         io.Writer
	Interactive bool
}

// Interaction 实现 ports.InteractionPort，支持真实本机 TTY（含 Unix /dev/tty 回退与 Windows Console）
// 以及确定性自定义流模式；零值恒不可交互并严格失败关闭。
//
//xops:opaque
//xops:failclosed
type Interaction struct {
	mu          sync.Mutex
	inFile      *os.File
	outFile     *os.File
	allowDevTTY bool

	streamMode  bool
	streamIn    io.Reader
	streamOut   io.Writer
	interactive bool
	valid       bool
}

// NewTTYInteraction 构造绑定当前进程标准输入/输出（Unix 下允许回退 /dev/tty）的交互适配器。
func NewTTYInteraction() *Interaction {
	inter, _ := probeFileTTYOS(os.Stdin, os.Stdout)
	if !inter {
		inter, _ = probeControllingTTYOS()
	}
	return &Interaction{
		inFile:      os.Stdin,
		outFile:     os.Stdout,
		allowDevTTY: true,
		interactive: inter,
		valid:       true,
	}
}

// NewFileInteraction 构造绑定显式文件句柄的交互适配器（不回退 /dev/tty，便于确定性测试非 TTY 拒绝路径）。
func NewFileInteraction(in, out *os.File) (*Interaction, error) {
	if in == nil || out == nil {
		return nil, fmt.Errorf("%w: 输入与输出文件句柄均不能为 nil", ports.ErrInvalidArgument)
	}
	inter, err := probeFileTTYOS(in, out)
	if err != nil {
		return nil, err
	}
	return &Interaction{
		inFile:      in,
		outFile:     out,
		interactive: inter,
		valid:       true,
	}, nil
}

// NewStreamInteraction 构造基于内存/管道流的确定性交互适配器，供 TCK 与上层测试驱动。
func NewStreamInteraction(spec StreamSpec) (*Interaction, error) {
	if spec.In == nil || spec.Out == nil {
		return nil, fmt.Errorf("%w: StreamSpec 的 In 与 Out 均不能为 nil", ports.ErrInvalidArgument)
	}
	return &Interaction{
		streamMode:  true,
		streamIn:    spec.In,
		streamOut:   spec.Out,
		interactive: spec.Interactive,
		valid:       true,
	}, nil
}

// CanInteract 报告当前适配器是否具备真实交互式终端能力（零值与非 TTY 管道恒返回 false）。
func (i *Interaction) CanInteract() bool {
	return i != nil && i.valid && i.interactive
}

// Confirm 向用户展示脱敏风险提示并要求显式输入 yes/y 确认，其他输入或空行一律失败关闭返回 VerdictDeny。
func (i *Interaction) Confirm(ctx context.Context, req ports.ConfirmRequest) (security.Verdict, error) {
	if err := i.checkContext(ctx); err != nil {
		return security.VerdictDeny, err
	}
	if !req.IsValid() {
		return security.VerdictDeny, fmt.Errorf("%w: ConfirmRequest 无效", ports.ErrInvalidArgument)
	}
	prompt := formatConfirmPrompt(req)
	line, err := i.promptLine(ctx, prompt, false)
	if err != nil {
		return security.VerdictDeny, err
	}
	defer clear(line)
	answer := strings.ToLower(strings.TrimSpace(string(line)))
	if answer == "y" || answer == "yes" {
		return security.VerdictAllow, nil
	}
	return security.VerdictDeny, nil
}

// PromptApproval 向用户展示不可变 ApprovalEnvelope 摘要并要求显式批准，响应强制绑定规范摘要（INV-E5）。
func (i *Interaction) PromptApproval(ctx context.Context, envelope security.ApprovalEnvelope) (ports.ApprovalDecisionResponse, error) {
	if err := i.checkContext(ctx); err != nil {
		return zeroVal[ports.ApprovalDecisionResponse](), err
	}
	if !envelope.IsValid() {
		return zeroVal[ports.ApprovalDecisionResponse](), fmt.Errorf("%w: ApprovalEnvelope 无效", ports.ErrInvalidArgument)
	}
	dig, err := envelope.Digest()
	if err != nil {
		return zeroVal[ports.ApprovalDecisionResponse](), err
	}
	prompt := formatApprovalPrompt(envelope, dig)
	line, err := i.promptLine(ctx, prompt, false)
	if err != nil {
		return zeroVal[ports.ApprovalDecisionResponse](), err
	}
	defer clear(line)
	answer := strings.ToLower(strings.TrimSpace(string(line)))
	verdict := security.VerdictDeny
	if answer == "approve" || answer == "yes" || answer == "y" {
		verdict = security.VerdictAllow
	}
	return ports.NewApprovalDecisionResponse(verdict, dig, "")
}

// PromptText 采集非敏感单行文本输入；当 !req.AllowEmpty() 且输入为空时拒绝返回 ErrInvalidArgument。
func (i *Interaction) PromptText(ctx context.Context, req ports.TextPromptRequest) (string, error) {
	if err := i.checkContext(ctx); err != nil {
		return "", err
	}
	if !req.IsValid() {
		return "", fmt.Errorf("%w: TextPromptRequest 无效", ports.ErrInvalidArgument)
	}
	prompt := formatTextPrompt(req.Title(), req.Subject(), req.Prompt())
	line, err := i.promptLine(ctx, prompt, false)
	if err != nil {
		return "", err
	}
	text := string(trimLineEnding(line))
	if text == "" && !req.AllowEmpty() {
		return "", fmt.Errorf("%w: 文本输入不能为空", ports.ErrInvalidArgument)
	}
	return text, nil
}

// PromptSecret 以无回显方式采集机密输入并在同步闭包内借出 *secret.SecretBox，退出前无条件清零。
//
//xops:syncclosure
//xops:borrowed
func (i *Interaction) PromptSecret(ctx context.Context, req ports.SecretPromptRequest, fn func(box *secret.SecretBox) error) error {
	if err := i.checkContext(ctx); err != nil {
		return err
	}
	if fn == nil {
		return ports.ErrNilCallback
	}
	if !req.IsValid() {
		return fmt.Errorf("%w: SecretPromptRequest 无效", ports.ErrInvalidArgument)
	}
	prompt := formatTextPrompt(req.Title(), req.Subject(), req.Prompt())
	line, err := i.promptLine(ctx, prompt, true)
	if err != nil {
		return err
	}
	defer clear(line)
	trimmed := trimLineEnding(line)
	if len(trimmed) == 0 && !req.AllowEmpty() {
		return fmt.Errorf("%w: 机密输入不能为空", ports.ErrInvalidArgument)
	}
	return secret.WithBytes(trimmed, func(box *secret.SecretBox) error { return fn(box) })
}

func (i *Interaction) checkContext(ctx context.Context) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if i == nil || !i.valid {
		return ports.ErrInteractionUnavailable
	}
	return nil
}

func (i *Interaction) promptLine(ctx context.Context, prompt string, noEcho bool) ([]byte, error) {
	if !i.CanInteract() {
		return nil, ports.ErrInteractionUnavailable
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.streamMode {
		return i.promptStreamLine(ctx, prompt)
	}
	return promptTTYLineOS(ctx, i.inFile, i.outFile, i.allowDevTTY, prompt, noEcho)
}

func (i *Interaction) promptStreamLine(ctx context.Context, prompt string) ([]byte, error) {
	if _, err := io.WriteString(i.streamOut, prompt); err != nil {
		return nil, err
	}
	return readBoundedStreamLine(ctx, i.streamIn)
}

func readBoundedStreamLine(ctx context.Context, r io.Reader) ([]byte, error) {
	var out []byte
	var one [1]byte
	for len(out) < maxPromptLineBytes {
		if err := ctx.Err(); err != nil {
			clear(out)
			return nil, err
		}
		n, err := r.Read(one[:])
		if n > 0 {
			if one[0] == '\n' {
				return out, nil
			}
			out = append(out, one[0])
		}
		if err != nil {
			return finishStreamLineOnErr(out, err)
		}
	}
	return out, nil
}

func finishStreamLineOnErr(out []byte, err error) ([]byte, error) {
	if errors.Is(err, io.EOF) {
		if len(out) > 0 {
			return out, nil
		}
		return nil, ports.ErrInteractionCanceled
	}
	clear(out)
	return nil, err
}

func formatConfirmPrompt(req ports.ConfirmRequest) string {
	var b strings.Builder
	b.WriteString("[")
	b.WriteString(security.SanitizePromptText(req.Risk().String()))
	b.WriteString("] ")
	if req.Title() != "" {
		b.WriteString(security.SanitizePromptText(req.Title()))
		b.WriteString(": ")
	}
	if req.Subject() != "" {
		b.WriteString("(")
		b.WriteString(security.SanitizePromptText(req.Subject()))
		b.WriteString(") ")
	}
	b.WriteString(security.SanitizePromptText(req.Message()))
	b.WriteString(" [y/N]: ")
	return b.String()
}

func formatApprovalPrompt(env security.ApprovalEnvelope, dig security.Digest) string {
	var b strings.Builder
	b.WriteString("[APPROVAL ")
	b.WriteString(security.SanitizePromptText(env.Risk().String()))
	b.WriteString("] ")
	b.WriteString(security.SanitizePromptText(env.ScopeSummary()))
	b.WriteString(" (digest=")
	b.WriteString(security.SanitizePromptText(dig.String()))
	b.WriteString(") [approve/N]: ")
	return b.String()
}

func formatTextPrompt(title, subject, prompt string) string {
	var b strings.Builder
	if title != "" {
		b.WriteString(security.SanitizePromptText(title))
		b.WriteString(": ")
	}
	if subject != "" {
		b.WriteString("(")
		b.WriteString(security.SanitizePromptText(subject))
		b.WriteString(") ")
	}
	b.WriteString(security.SanitizePromptText(prompt))
	if !strings.HasSuffix(prompt, " ") {
		b.WriteString(" ")
	}
	return b.String()
}

func trimLineEnding(raw []byte) []byte {
	return bytes.TrimRight(raw, "\r\n")
}
