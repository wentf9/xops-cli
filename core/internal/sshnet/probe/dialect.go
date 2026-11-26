package probe

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/execution"
)

const (
	// 阶段 1 合法方言探针：POSIX 使用 if/then 语法，防止 Unix PowerShell 7 误解析 printf 与 $() 命令替换。
	stage1ProbePOSIX      = `if :; then printf '__XOPS_DIALECT_POSIX__:%s:%s\n' "$(uname -s 2>/dev/null || echo UNAME_FAIL)" "$SHELL"; fi`
	stage1ProbeCmd        = `echo __XOPS_DIALECT_CMD__:%COMSPEC%`
	stage1ProbePowerShell = `Write-Output ('__XOPS_DIALECT_POWERSHELL__:' + $PSVersionTable.PSVersion.ToString()); Write-Output ('__XOPS_PLATFORM__:' + [Environment]::OSVersion.Platform)`

	// 阶段 2 解释器枚举探针：严格限定为 v2 领域层支持的 6 种具名解释器，并以显式结束帧收口防半包误判。
	stage2EnumPOSIX      = `sh -c 'for i in bash sh zsh powershell pwsh cmd; do if command -v "$i" >/dev/null 2>&1; then printf "__XOPS_INTERP__:%s\n" "$i"; fi; done; printf "__XOPS_INTERP_END__\n"'`
	stage2EnumCmd        = `cmd.exe /d /s /c "where bash.exe >nul 2>&1 && (echo __XOPS_INTERP__:bash) & where sh.exe >nul 2>&1 && (echo __XOPS_INTERP__:sh) & where zsh.exe >nul 2>&1 && (echo __XOPS_INTERP__:zsh) & where powershell.exe >nul 2>&1 && (echo __XOPS_INTERP__:powershell) & where pwsh.exe >nul 2>&1 && (echo __XOPS_INTERP__:pwsh) & (echo __XOPS_INTERP__:cmd) & (echo __XOPS_INTERP_END__) & exit /b 0"`
	stage2EnumPowerShell = `& { $previous = $global:PSModuleAutoLoadingPreference; try { $global:PSModuleAutoLoadingPreference = 'None'; foreach ($i in @('bash','sh','zsh','powershell','pwsh','cmd')) { if (Get-Command $i -CommandType Application -ListImported -ErrorAction SilentlyContinue) { [Console]::WriteLine('__XOPS_INTERP__:' + $i) } }; [Console]::WriteLine('__XOPS_INTERP_END__') } finally { $global:PSModuleAutoLoadingPreference = $previous } }`

	framePrefixPOSIX      = "__XOPS_DIALECT_POSIX__:"
	framePrefixCmd        = "__XOPS_DIALECT_CMD__:"
	framePrefixPowerShell = "__XOPS_DIALECT_POWERSHELL__:"
	framePrefixPlatform   = "__XOPS_PLATFORM__:"
	framePrefixInterp     = "__XOPS_INTERP__:"
	frameInterpEnd        = "__XOPS_INTERP_END__"
)

type stage1ProbeSpec struct {
	dialect execution.LaunchDialect
	command string
}

type stage1Hit struct {
	dialect   execution.LaunchDialect
	osFamily  string
	shellPath string
	rawBanner string
}

func stage1ProbeSequence(preferWindows bool) []stage1ProbeSpec {
	posix := stage1ProbeSpec{dialect: execution.DialectPOSIX, command: stage1ProbePOSIX}
	cmd := stage1ProbeSpec{dialect: execution.DialectCmd, command: stage1ProbeCmd}
	ps := stage1ProbeSpec{dialect: execution.DialectPowerShell, command: stage1ProbePowerShell}
	if preferWindows {
		return []stage1ProbeSpec{cmd, ps, posix}
	}
	return []stage1ProbeSpec{posix, cmd, ps}
}

func stage2EnumCommand(dialect execution.LaunchDialect) (string, error) {
	switch dialect {
	case execution.DialectPOSIX:
		return stage2EnumPOSIX, nil
	case execution.DialectCmd:
		return stage2EnumCmd, nil
	case execution.DialectPowerShell:
		return stage2EnumPowerShell, nil
	default:
		return "", fmt.Errorf("%w: 无法在方言 %s 上执行阶段 2 解释器枚举", ErrProbeFailed, dialect)
	}
}

// extractSingleFrame 从输出行中提取唯一匹配 prefix 的帧载荷；重复帧、超长或含 NUL/CR 一律失败关闭。
func extractSingleFrame(output, prefix string) (string, bool) {
	var frame string
	found := false
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSuffix(line, "\r")
		val, ok := strings.CutPrefix(line, prefix)
		if !ok {
			continue
		}
		if found || len(val) > maxFrameValueBytes || strings.ContainsAny(val, "\x00\r") {
			return "", false
		}
		frame, found = val, true
	}
	return frame, found
}

func parseStage1Output(dialect execution.LaunchDialect, output string) (stage1Hit, bool) {
	switch dialect {
	case execution.DialectPOSIX:
		return parsePOSIXStage1(output)
	case execution.DialectCmd:
		return parseCmdStage1(output)
	case execution.DialectPowerShell:
		return parsePowerShellStage1(output)
	default:
		return stage1Hit{}, false
	}
}

func parsePOSIXStage1(output string) (stage1Hit, bool) {
	frame, ok := extractSingleFrame(output, framePrefixPOSIX)
	if !ok {
		return stage1Hit{}, false
	}
	rawOS, shellPath, hasColon := strings.Cut(frame, ":")
	if !hasColon || rawOS == "" || (shellPath != "" && !strings.HasPrefix(shellPath, "/")) {
		return stage1Hit{}, false
	}
	banner := "posix"
	if shellPath != "" {
		banner = "posix:" + shellPath
	}
	return stage1Hit{
		dialect:   execution.DialectPOSIX,
		osFamily:  normalizeOSFamily(rawOS),
		shellPath: shellPath,
		rawBanner: banner,
	}, true
}

func parseCmdStage1(output string) (stage1Hit, bool) {
	frame, ok := extractSingleFrame(output, framePrefixCmd)
	if !ok || len(frame) <= 3 || frame[1] != ':' || (frame[2] != '\\' && frame[2] != '/') {
		return stage1Hit{}, false
	}
	if !strings.HasSuffix(strings.ToLower(frame), "cmd.exe") {
		return stage1Hit{}, false
	}
	return stage1Hit{
		dialect:   execution.DialectCmd,
		osFamily:  "windows",
		shellPath: frame,
		rawBanner: "cmd:" + frame,
	}, true
}

func parsePowerShellStage1(output string) (stage1Hit, bool) {
	ver, ok := extractSingleFrame(output, framePrefixPowerShell)
	if !ok || !isValidDottedVersion(ver) {
		return stage1Hit{}, false
	}
	osFamily := ""
	if plat, found := extractSingleFrame(output, framePrefixPlatform); found {
		osFamily = normalizeOSFamily(plat)
	}
	return stage1Hit{
		dialect:   execution.DialectPowerShell,
		osFamily:  osFamily,
		rawBanner: "powershell:" + ver,
	}, true
}

func isValidDottedVersion(raw string) bool {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return false
	}
	for _, p := range parts {
		if !isASCIIDigits(p) {
			return false
		}
	}
	return true
}

func isASCIIDigits(s string) bool {
	if s == "" || len(s) > 10 {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// parseStage2Interpreters 严格解析阶段 2 解释器枚举帧：
// 要求精确出现一次 __XOPS_INTERP_END__，且全部条目均在合法集合内、无重复、无结束帧后残留。
func parseStage2Interpreters(output string) ([]execution.Interpreter, error) {
	var out []execution.Interpreter
	ended := false
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == frameInterpEnd {
			if ended {
				return nil, fmt.Errorf("%w: 阶段 2 出现重复结束帧", ErrProbeFailed)
			}
			ended = true
			continue
		}
		val, ok := strings.CutPrefix(line, framePrefixInterp)
		if !ok {
			continue
		}
		interp, err := parseAllowedProbeInterpreter(val)
		if ended || err != nil || slices.Contains(out, interp) {
			return nil, fmt.Errorf("%w: 阶段 2 解释器帧非法或重复", ErrProbeFailed)
		}
		out = append(out, interp)
	}
	if !ended {
		return nil, fmt.Errorf("%w: 阶段 2 缺失结束帧", ErrProbeFailed)
	}
	return out, nil
}

func parseAllowedProbeInterpreter(raw string) (execution.Interpreter, error) {
	interp, err := execution.ParseInterpreter(raw)
	if err != nil || interp == execution.InterpreterServer {
		return execution.InterpreterInvalid, ErrProbeFailed
	}
	return interp, nil
}

func selectRecommendedInterpreter(hit stage1Hit, available []execution.Interpreter) (execution.Interpreter, bool) {
	switch hit.dialect {
	case execution.DialectPOSIX:
		return selectPOSIXInterpreter(hit.shellPath, available)
	case execution.DialectCmd:
		return firstAvailableInterpreter(available, execution.InterpreterCmd, execution.InterpreterPowerShell, execution.InterpreterPwsh)
	case execution.DialectPowerShell:
		if hit.osFamily == "windows" {
			return firstAvailableInterpreter(available, execution.InterpreterPowerShell, execution.InterpreterPwsh)
		}
		return firstAvailableInterpreter(available, execution.InterpreterPwsh, execution.InterpreterPowerShell)
	default:
		return execution.InterpreterInvalid, false
	}
}

func selectPOSIXInterpreter(remoteShellPath string, available []execution.Interpreter) (execution.Interpreter, bool) {
	if pref, ok := allowlistedPOSIXShellBase(remoteShellPath); ok && slices.Contains(available, pref) {
		return pref, true
	}
	return firstAvailableInterpreter(available, execution.InterpreterBash, execution.InterpreterSH, execution.InterpreterZsh)
}

func allowlistedPOSIXShellBase(remoteShellPath string) (execution.Interpreter, bool) {
	if remoteShellPath == "" {
		return execution.InterpreterInvalid, false
	}
	switch path.Base(remoteShellPath) {
	case "bash":
		return execution.InterpreterBash, true
	case "sh", "ash", "dash":
		return execution.InterpreterSH, true
	case "zsh":
		return execution.InterpreterZsh, true
	default:
		return execution.InterpreterInvalid, false
	}
}

func firstAvailableInterpreter(available []execution.Interpreter, order ...execution.Interpreter) (execution.Interpreter, bool) {
	for _, cand := range order {
		if slices.Contains(available, cand) {
			return cand, true
		}
	}
	return execution.InterpreterInvalid, false
}

func normalizeOSFamily(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case lower == "" || lower == "uname_fail":
		return ""
	case lower == "linux":
		return "linux"
	case lower == "darwin" || lower == "macosx":
		return "darwin"
	case lower == "freebsd":
		return "freebsd"
	case lower == "openbsd":
		return "openbsd"
	case lower == "netbsd":
		return "netbsd"
	case lower == "win32nt" || lower == "windows_nt" || lower == "windows" ||
		strings.HasPrefix(lower, "mingw") || strings.HasPrefix(lower, "msys") || strings.HasPrefix(lower, "cygwin"):
		return "windows"
	case lower == "unix":
		return "unix"
	default:
		return sanitizeOSFamilyToken(lower)
	}
}

func sanitizeOSFamilyToken(lower string) string {
	var b strings.Builder
	for i := range len(lower) {
		c := lower[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			b.WriteByte(c)
		}
	}
	return b.String()
}
