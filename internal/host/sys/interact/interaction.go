package interact

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// StreamSpec 是构造基于自定义输入/输出流的确定性 Interaction 的显式入参规格（供 TCK 与单元测试使用）。
// Localizer 为可选配置；为 nil 或无效时自动回退至内置英文默认 Localizer。
type StreamSpec struct {
	In          io.Reader
	Out         io.Writer
	Interactive bool
	Localizer   *i18n.Localizer
}

// Interaction 实现 ports.InteractionPort，支持真实本机 TTY（含 Unix /dev/tty 回退与 Windows Console）
// 以及确定性自定义流模式；持有并发安全可热替换的本地化渲染器，零值恒不可交互并严格失败关闭。
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
	localizer   atomic.Pointer[i18n.Localizer]
	fallbackLoc *i18n.Localizer
	valid       bool
}

// NewTTYInteraction 构造绑定当前进程标准输入/输出（Unix 下允许回退 /dev/tty）的交互适配器。
func NewTTYInteraction() *Interaction {
	inter, _ := probeFileTTYOS(os.Stdin, os.Stdout)
	if !inter {
		inter, _ = probeControllingTTYOS()
	}
	ui := &Interaction{
		inFile:      os.Stdin,
		outFile:     os.Stdout,
		allowDevTTY: true,
		interactive: inter,
		valid:       true,
	}
	ui.initLocalizer(nil)
	return ui
}

// NewFileInteraction 构造绑定显式文件句柄的交互适配器（不回退 /dev/tty，便于确定性测试非 TTY 拒绝路径）。
func NewFileInteraction(in, out *os.File) (*Interaction, error) {
	if in == nil || out == nil {
		return nil, i18n.EF(ports.ErrInvalidArgument, i18n.KeyInteractNilFileHandles)
	}
	inter, err := probeFileTTYOS(in, out)
	if err != nil {
		return nil, err
	}
	ui := &Interaction{
		inFile:      in,
		outFile:     out,
		interactive: inter,
		valid:       true,
	}
	ui.initLocalizer(nil)
	return ui, nil
}

// NewStreamInteraction 构造基于内存/管道流的确定性交互适配器，供 TCK 与上层测试驱动。
func NewStreamInteraction(spec StreamSpec) (*Interaction, error) {
	if spec.In == nil || spec.Out == nil {
		return nil, i18n.EF(ports.ErrInvalidArgument, i18n.KeyInteractNilStreamHandles)
	}
	ui := &Interaction{
		streamMode:  true,
		streamIn:    spec.In,
		streamOut:   spec.Out,
		interactive: spec.Interactive,
		valid:       true,
	}
	ui.initLocalizer(spec.Localizer)
	return ui, nil
}

// SetLocalizer 并发安全地热切换当前交互适配器使用的本地化渲染器（供 TUI 切换语言后同步 SSH 接管提示）。
// 接收者为 nil 或未初始化时安全忽略；传入 nil 或无效 Localizer 时回退至规范英文渲染器。
func (i *Interaction) SetLocalizer(loc *i18n.Localizer) {
	if i == nil || !i.valid {
		return
	}
	if loc != nil && loc.IsValid() {
		i.localizer.Store(loc)
		return
	}
	i.localizer.Store(nil)
}

func (i *Interaction) initLocalizer(loc *i18n.Localizer) {
	if loc != nil && loc.IsValid() {
		i.fallbackLoc = loc.WithLocale(domi18n.LocaleEn)
		i.localizer.Store(loc)
		return
	}
	if defLoc, err := i18n.DefaultLocalizer(); err == nil && defLoc.IsValid() {
		i.fallbackLoc = defLoc
		i.localizer.Store(defLoc)
	}
}

func (i *Interaction) activeLocalizer() *i18n.Localizer {
	if i == nil || !i.valid {
		return nil
	}
	if loc := i.localizer.Load(); loc != nil && loc.IsValid() {
		return loc
	}
	if i.fallbackLoc != nil && i.fallbackLoc.IsValid() {
		return i.fallbackLoc
	}
	return nil
}

// CanInteract 报告当前适配器是否具备真实交互式终端能力（零值与非 TTY 管道恒返回 false）。
func (i *Interaction) CanInteract() bool {
	return i != nil && i.valid && i.interactive
}

// Confirm 向用户展示脱敏并本地化的风险提示并要求显式输入 ASCII yes/y 确认，其他输入或空行一律失败关闭返回 VerdictDeny。
func (i *Interaction) Confirm(ctx context.Context, req ports.ConfirmRequest) (security.Verdict, error) {
	if err := i.checkContext(ctx); err != nil {
		return security.VerdictDeny, err
	}
	if !req.IsValid() {
		return security.VerdictDeny, i18n.EF(ports.ErrInvalidArgument, i18n.KeyInteractInvalidRequest, i18n.Str("kind", "ConfirmRequest"))
	}
	prompt := formatConfirmPrompt(i.activeLocalizer(), req)
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

// PromptApproval 向用户展示不可变 ApprovalEnvelope 摘要并要求显式输入 ASCII 批准词，响应强制绑定规范摘要（INV-E5）。
func (i *Interaction) PromptApproval(ctx context.Context, envelope security.ApprovalEnvelope) (ports.ApprovalDecisionResponse, error) {
	if err := i.checkContext(ctx); err != nil {
		return zeroVal[ports.ApprovalDecisionResponse](), err
	}
	if !envelope.IsValid() {
		return zeroVal[ports.ApprovalDecisionResponse](), i18n.EF(ports.ErrInvalidArgument, i18n.KeyInteractInvalidRequest, i18n.Str("kind", "ApprovalEnvelope"))
	}
	dig, err := envelope.Digest()
	if err != nil {
		return zeroVal[ports.ApprovalDecisionResponse](), err
	}
	prompt := formatApprovalPrompt(i.activeLocalizer(), envelope, dig)
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
		return "", i18n.EF(ports.ErrInvalidArgument, i18n.KeyInteractInvalidRequest, i18n.Str("kind", "TextPromptRequest"))
	}
	prompt := formatTextPrompt(i.activeLocalizer(), req.TitleMessage(), req.Title(), req.Subject(), req.BodyMessage(), req.Prompt())
	line, err := i.promptLine(ctx, prompt, false)
	if err != nil {
		return "", err
	}
	text := string(trimLineEnding(line))
	if text == "" && !req.AllowEmpty() {
		return "", i18n.EF(ports.ErrInvalidArgument, i18n.KeyInteractEmptyText)
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
		return i18n.EF(ports.ErrInvalidArgument, i18n.KeyInteractInvalidRequest, i18n.Str("kind", "SecretPromptRequest"))
	}
	prompt := formatTextPrompt(i.activeLocalizer(), req.TitleMessage(), req.Title(), req.Subject(), req.BodyMessage(), req.Prompt())
	line, err := i.promptLine(ctx, prompt, true)
	if err != nil {
		return err
	}
	defer clear(line)
	trimmed := trimLineEnding(line)
	if len(trimmed) == 0 && !req.AllowEmpty() {
		return i18n.EF(ports.ErrInvalidArgument, i18n.KeyInteractEmptySecret)
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
	for {
		if err := ctx.Err(); err != nil {
			clear(out)
			return nil, err
		}
		n, err := r.Read(one[:])
		if n > 0 {
			if one[0] == '\n' {
				return out, nil
			}
			if len(out) >= maxPromptLineBytes {
				clear(out)
				drainStreamToNewline(ctx, r)
				return nil, i18n.EF(ports.ErrLimitExceeded, i18n.KeyInteractLineTooLong, i18n.Int("max", maxPromptLineBytes))
			}
			out = append(out, one[0])
		}
		if err != nil {
			return finishStreamLineOnErr(out, err)
		}
	}
}

func drainStreamToNewline(ctx context.Context, r io.Reader) {
	var one [1]byte
	for ctx.Err() == nil {
		n, err := r.Read(one[:])
		if (n > 0 && one[0] == '\n') || err != nil {
			return
		}
	}
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

func formatConfirmPrompt(loc *i18n.Localizer, req ports.ConfirmRequest) string {
	var b strings.Builder
	b.WriteString("[")
	b.WriteString(security.SanitizePromptText(localizeRiskLevel(loc, req.Risk())))
	b.WriteString("] ")
	if title := security.SanitizePromptText(renderOptionalMessage(loc, req.TitleMessage(), req.Title())); title != "" {
		b.WriteString(title)
		b.WriteString(": ")
	}
	if req.Subject() != "" {
		b.WriteString("(")
		b.WriteString(security.SanitizePromptText(req.Subject()))
		b.WriteString(") ")
	}
	body := security.SanitizePromptText(renderOptionalMessage(loc, req.BodyMessage(), req.Message()))
	if body == "" {
		body = security.SanitizePromptText(req.Message())
	}
	b.WriteString(body)
	b.WriteString(" [y/N]: ")
	return b.String()
}

func formatApprovalPrompt(loc *i18n.Localizer, env security.ApprovalEnvelope, dig security.Digest) string {
	var b strings.Builder
	b.WriteString("[")
	b.WriteString(security.SanitizePromptText(localizeLabel(loc, i18n.KeyInteractApprovalBanner, "APPROVAL")))
	b.WriteString(" ")
	b.WriteString(security.SanitizePromptText(localizeRiskLevel(loc, env.Risk())))
	b.WriteString("] ")
	b.WriteString(security.SanitizePromptText(env.ScopeSummary()))
	b.WriteString(" (")
	b.WriteString(security.SanitizePromptText(localizeLabel(loc, i18n.KeyInteractApprovalDigestLabel, "digest")))
	b.WriteString("=")
	b.WriteString(security.SanitizePromptText(dig.String()))
	b.WriteString(") [approve/N]: ")
	return b.String()
}

func formatTextPrompt(
	loc *i18n.Localizer,
	titleMsg algebraic.Option[domi18n.Message],
	fallbackTitle string,
	subject string,
	bodyMsg algebraic.Option[domi18n.Message],
	fallbackBody string,
) string {
	var b strings.Builder
	if title := security.SanitizePromptText(renderOptionalMessage(loc, titleMsg, fallbackTitle)); title != "" {
		b.WriteString(title)
		b.WriteString(": ")
	}
	if subject != "" {
		b.WriteString("(")
		b.WriteString(security.SanitizePromptText(subject))
		b.WriteString(") ")
	}
	sanitized := security.SanitizePromptText(renderOptionalMessage(loc, bodyMsg, fallbackBody))
	if sanitized == "" {
		sanitized = security.SanitizePromptText(fallbackBody)
	}
	b.WriteString(sanitized)
	if !strings.HasSuffix(sanitized, " ") {
		b.WriteString(" ")
	}
	return b.String()
}

func renderOptionalMessage(loc *i18n.Localizer, opt algebraic.Option[domi18n.Message], fallback string) string {
	if msg, ok := opt.Get(); ok && msg.IsValid() {
		if rendered := loc.Render(msg); rendered != "" {
			return rendered
		}
	}
	return fallback
}

func localizeRiskLevel(loc *i18n.Localizer, risk security.RiskLevel) string {
	if loc == nil || !loc.IsValid() {
		return risk.String()
	}
	switch risk {
	case security.RiskSafe:
		return localizeLabel(loc, i18n.KeyInteractRiskSafe, risk.String())
	case security.RiskModerate:
		return localizeLabel(loc, i18n.KeyInteractRiskModerate, risk.String())
	case security.RiskDangerous:
		return localizeLabel(loc, i18n.KeyInteractRiskDangerous, risk.String())
	case security.RiskUnknown:
		return localizeLabel(loc, i18n.KeyInteractRiskUnknown, risk.String())
	default:
		return localizeLabel(loc, i18n.KeyInteractRiskUnknown, risk.String())
	}
}

func localizeLabel(loc *i18n.Localizer, id domi18n.MessageID, enFallback string) string {
	if loc == nil || !loc.IsValid() {
		return enFallback
	}
	if text := loc.T(id); text != "" && text != string(id) {
		return text
	}
	return enFallback
}

func trimLineEnding(raw []byte) []byte {
	return bytes.TrimRight(raw, "\r\n")
}
