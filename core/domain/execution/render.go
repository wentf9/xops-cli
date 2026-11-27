package execution

import (
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
)

// RenderCommand 按启动方言、解释器、登录模式、工作目录与环境变量确定性渲染远端执行命令行（零 OS 调用）。
// 对于 PlanKindScript，RenderCommand 输出目标解释器标准输入消费命令：
//   - POSIX：无位置参数时为 "<interp> [-l] -s"，携带位置参数 Argv 时为 "<interp> [-l] -s -- <QuotePOSIX(arg)...>"；
//   - PowerShell：恒为 "<exe> -NoProfile -NonInteractive -Command -"，前言、脚本正文与位置参数均经 StdinPayload() 投递。
func (p CommandPlan) RenderCommand() (string, error) {
	if !p.IsValid() {
		return "", ErrInvalidCommandPlan
	}
	switch p.profile.Interpreter() {
	case InterpreterServer:
		return p.renderServerCommand()
	case InterpreterSH, InterpreterBash, InterpreterZsh:
		return p.renderPOSIXInterpreter()
	case InterpreterPowerShell, InterpreterPwsh:
		return p.renderPowerShellInterpreter()
	case InterpreterCmd:
		return p.renderCmdInterpreter()
	default:
		return "", ErrUnsupportedExecutionCombination
	}
}

// StdinPayload 返回需要经远端 stdin 投递的脚本完整载荷（含在目标解释器内执行的 WorkDir/Env 前言与脚本正文；
// PowerShell 携带位置参数 Argv 时以 "& {\n<script>\n} <QuotePowerShell(arg)...>" 形式安全传参）。
// PlanKindCommand 或无效零值恒返回 ("", false)，实现 (RenderCommand, StdinPayload) 显式统一执行契约。
func (p CommandPlan) StdinPayload() (string, bool) {
	if !p.IsValid() || p.kind != PlanKindScript {
		return "", false
	}
	switch p.profile.Interpreter() {
	case InterpreterSH, InterpreterBash, InterpreterZsh:
		prefix := buildPOSIXPrefixTrusted(p.workDir, p.env)
		if prefix == "" {
			return p.command, true
		}
		return strings.TrimRight(prefix, " ") + "\n" + p.command, true
	case InterpreterPowerShell, InterpreterPwsh:
		body := p.command
		if len(p.argv) > 0 {
			body = "& {\n" + p.command + "\n} " + joinQuotedTrusted(p.argv, quotePowerShellTrusted)
		}
		prologue := buildPowerShellPrologueTrusted(p.workDir, p.env)
		if len(prologue) == 0 {
			return body, true
		}
		return strings.Join(prologue, "; ") + "\n" + body, true
	default:
		return "", false
	}
}

// validateScriptStdin 在构造期校验脚本模式经 stdin 投递时涉及的 WorkDir/Env 前言与 PowerShell 位置参数均可安全引用。
func (p CommandPlan) validateScriptStdin() error {
	if p.kind != PlanKindScript {
		return nil
	}
	switch p.profile.Interpreter() {
	case InterpreterSH, InterpreterBash, InterpreterZsh:
		_, err := buildPOSIXPrefix(p.workDir, p.env)
		return err
	case InterpreterPowerShell, InterpreterPwsh:
		if _, err := buildPowerShellPrologue(p.workDir, p.env); err != nil {
			return err
		}
		if len(p.argv) > 0 {
			if _, err := joinQuoted(p.argv, QuotePowerShell); err != nil {
				return err
			}
		}
		return nil
	default:
		return ErrUnsupportedExecutionCombination
	}
}

func (p CommandPlan) renderServerCommand() (string, error) {
	dialect := p.profile.Dialect()
	if p.workDir.IsSome() || len(p.env) > 0 || len(p.argv) > 0 {
		if dialect == DialectUnknown || dialect == DialectRaw {
			return "", domi18n.EF(ErrUnsupportedExecutionCombination, domi18n.KeyExecutionProfileMismatch, domi18n.Str("dialect", dialect.String()), domi18n.Str("interpreter", InterpreterServer.String()))
		}
	}
	if dialect == DialectUnknown || dialect == DialectRaw {
		return p.command, nil
	}
	switch dialect {
	case DialectPOSIX:
		return p.renderPOSIXBody()
	case DialectPowerShell:
		return p.renderPowerShellBody()
	case DialectCmd:
		return p.renderCmdBody()
	default:
		return "", ErrUnsupportedExecutionCombination
	}
}

func (p CommandPlan) renderPOSIXBody() (string, error) {
	body := p.command
	if len(p.argv) > 0 {
		var err error
		if body, err = joinQuoted(p.argv, QuotePOSIX); err != nil {
			return "", err
		}
	}
	prefix, err := buildPOSIXPrefix(p.workDir, p.env)
	if err != nil {
		return "", err
	}
	return prefix + body, nil
}

func (p CommandPlan) renderPOSIXInterpreter() (string, error) {
	interp := p.profile.Interpreter().String()
	loginFlag := pickIf(p.profile.LoginMode() == LoginModeLogin, " -l", "")
	if p.kind == PlanKindScript {
		base := interp + loginFlag + " -s"
		if len(p.argv) == 0 {
			return base, nil
		}
		quoted, err := joinQuoted(p.argv, QuotePOSIX)
		if err != nil {
			return "", err
		}
		return base + " -- " + quoted, nil
	}
	inner, err := p.renderPOSIXBody()
	if err != nil {
		return "", err
	}
	quoted, err := QuotePOSIX(inner)
	if err != nil {
		return "", err
	}
	return interp + loginFlag + " -c " + quoted, nil
}

// buildPOSIXPrefix 发射失败即退出的 POSIX 前言（cd/export 任一失败立即 exit $?，杜绝经 ';' 或 '\n' 跌落至错目录执行）。
func buildPOSIXPrefix(wdOpt algebraic.Option[pathalg.RemotePath], env []envEntry) (string, error) {
	if wd, ok := wdOpt.Get(); ok {
		if _, err := QuotePOSIX(wd.String()); err != nil {
			return "", err
		}
	}
	for _, kv := range env {
		if _, err := QuotePOSIX(kv.value); err != nil {
			return "", err
		}
	}
	return buildPOSIXPrefixTrusted(wdOpt, env), nil
}

func buildPOSIXPrefixTrusted(wdOpt algebraic.Option[pathalg.RemotePath], env []envEntry) string {
	var b strings.Builder
	if wd, ok := wdOpt.Get(); ok {
		b.WriteString("cd -- ")
		b.WriteString(quotePOSIXTrusted(wd.String()))
		b.WriteString(" || exit $?; ")
	}
	for _, kv := range env {
		b.WriteString("export ")
		b.WriteString(kv.key)
		b.WriteByte('=')
		b.WriteString(quotePOSIXTrusted(kv.value))
		b.WriteString(" || exit $?; ")
	}
	return b.String()
}

func buildPowerShellPrologue(wdOpt algebraic.Option[pathalg.RemotePath], env []envEntry) ([]string, error) {
	if wd, ok := wdOpt.Get(); ok {
		if _, err := QuotePowerShell(wd.String()); err != nil {
			return nil, err
		}
	}
	for _, kv := range env {
		if _, err := QuotePowerShell(kv.value); err != nil {
			return nil, err
		}
	}
	return buildPowerShellPrologueTrusted(wdOpt, env), nil
}

func buildPowerShellPrologueTrusted(wdOpt algebraic.Option[pathalg.RemotePath], env []envEntry) []string {
	var lines []string
	if wd, ok := wdOpt.Get(); ok {
		lines = append(lines, "Set-Location -LiteralPath "+quotePowerShellTrusted(wd.String())+" -ErrorAction Stop")
	}
	for _, kv := range env {
		lines = append(lines, fmt.Sprintf("$env:%s = %s", kv.key, quotePowerShellTrusted(kv.value)))
	}
	return lines
}

func (p CommandPlan) renderPowerShellBody() (string, error) {
	lines, err := buildPowerShellPrologue(p.workDir, p.env)
	if err != nil {
		return "", err
	}
	body := p.command
	if len(p.argv) > 0 {
		quoted, err := joinQuoted(p.argv, QuotePowerShell)
		if err != nil {
			return "", err
		}
		body = "& " + quoted
	}
	lines = append(lines, body)
	return strings.Join(lines, "; "), nil
}

func (p CommandPlan) renderPowerShellInterpreter() (string, error) {
	exe := pickIf(p.profile.Interpreter() == InterpreterPwsh, "pwsh", "powershell.exe")
	if p.kind == PlanKindScript {
		return exe + " -NoProfile -NonInteractive -Command -", nil
	}
	script, err := p.renderPowerShellBody()
	if err != nil {
		return "", err
	}
	encoded, err := EncodePowerShellUTF16LEBase64(script)
	if err != nil {
		return "", err
	}
	cmd := exe + " -NoProfile -NonInteractive -EncodedCommand " + encoded
	if len(cmd) > maxWindowsCommandLineChars {
		return "", domi18n.EF(ErrInvalidCommandPlan, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "powershell_command"), domi18n.Int("size", len(cmd)), domi18n.Int("limit", maxWindowsCommandLineChars))
	}
	return cmd, nil
}

func (p CommandPlan) renderCmdBody() (string, error) {
	if p.kind == PlanKindScript {
		return "", domi18n.EF(ErrUnsupportedExecutionCombination, domi18n.KeyExecutionScriptInterpreter)
	}
	var parts []string
	if wd, ok := p.workDir.Get(); ok {
		q, err := QuoteCmdArg(wd.String())
		if err != nil {
			return "", err
		}
		parts = append(parts, "cd /d "+q+" || exit 1")
	}
	for _, kv := range p.env {
		if err := validateCmdText(kv.value, "cmd_env_value"); err != nil {
			return "", err
		}
		parts = append(parts, fmt.Sprintf(`set "%s=%s"`, kv.key, kv.value))
	}
	body := p.command
	if len(p.argv) > 0 {
		var err error
		if body, err = joinQuoted(p.argv, QuoteCmdArg); err != nil {
			return "", err
		}
	}
	parts = append(parts, body)
	rendered := strings.Join(parts, " && ")
	if strings.ContainsAny(rendered, "\r\n") {
		return "", domi18n.EF(ErrInvalidShellQuote, domi18n.KeyExecutionQuoteForbiddenChar, domi18n.Str("field", "cmd_command"))
	}
	return rendered, nil
}

func (p CommandPlan) renderCmdInterpreter() (string, error) {
	body, err := p.renderCmdBody()
	if err != nil {
		return "", err
	}
	return `cmd.exe /d /s /c "` + body + `"`, nil
}

func joinQuoted(args []string, quote func(string) (string, error)) (string, error) {
	out := make([]string, len(args))
	for i, arg := range args {
		q, err := quote(arg)
		if err != nil {
			return "", err
		}
		out[i] = q
	}
	return strings.Join(out, " "), nil
}

func joinQuotedTrusted(args []string, quote func(string) string) string {
	out := make([]string, len(args))
	for i, arg := range args {
		out[i] = quote(arg)
	}
	return strings.Join(out, " ")
}
