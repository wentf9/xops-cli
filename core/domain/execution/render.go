package execution

import (
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
)

// RenderCommand 按启动方言、解释器、登录模式、工作目录与环境变量确定性渲染远端执行命令行（零 OS 调用）。
// 对于 PlanKindScript，RenderCommand 仅输出目标解释器标准输入消费命令（POSIX: "<interp> [-l] -s"；
// PowerShell: "<exe> -NoProfile -NonInteractive -Command -"），完整前言与脚本正文经 StdinPayload() 投递。
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

// StdinPayload 返回需要经远端 stdin 投递的脚本完整载荷（含在目标解释器内执行的 WorkDir/Env 前言与脚本正文）。
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
		prologue := buildPowerShellPrologueTrusted(p.workDir, p.env)
		if len(prologue) == 0 {
			return p.command, true
		}
		return strings.Join(prologue, "; ") + "\n" + p.command, true
	default:
		return "", false
	}
}

// validateScriptStdin 在构造期校验脚本模式经 stdin 投递时涉及的 WorkDir/Env 前言均可被目标解释器安全引用。
func (p CommandPlan) validateScriptStdin() error {
	if p.kind != PlanKindScript {
		return nil
	}
	switch p.profile.Interpreter() {
	case InterpreterSH, InterpreterBash, InterpreterZsh:
		_, err := buildPOSIXPrefix(p.workDir, p.env)
		return err
	case InterpreterPowerShell, InterpreterPwsh:
		_, err := buildPowerShellPrologue(p.workDir, p.env)
		return err
	default:
		return ErrUnsupportedExecutionCombination
	}
}

func (p CommandPlan) renderServerCommand() (string, error) {
	dialect := p.profile.Dialect()
	if p.workDir.IsSome() || len(p.env) > 0 || len(p.argv) > 0 {
		if dialect == DialectUnknown || dialect == DialectRaw {
			return "", fmt.Errorf("%w: server 在 %s 方言下不支持拼接 cwd/env/argv", ErrUnsupportedExecutionCombination, dialect)
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
		return interp + loginFlag + " -s", nil
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
		return "", fmt.Errorf("%w: PowerShell -EncodedCommand 长度 %d 超过 Windows 命令行上限 %d", ErrInvalidCommandPlan, len(cmd), maxWindowsCommandLineChars)
	}
	return cmd, nil
}

func (p CommandPlan) renderCmdBody() (string, error) {
	if p.kind == PlanKindScript {
		return "", fmt.Errorf("%w: cmd 解释器不支持脚本模式", ErrUnsupportedExecutionCombination)
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
		if err := validateCmdText(kv.value, "cmd 环境变量值"); err != nil {
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
		return "", fmt.Errorf("%w: cmd.exe 命令禁止包含换行符", ErrInvalidShellQuote)
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
