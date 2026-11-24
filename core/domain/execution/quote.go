package execution

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/wentf9/xops-cli/core/domain/security"
)

// QuotePOSIX 使用 POSIX 单引号规则对单个参数执行无 OS 依赖的安全引用。
// 拒绝 NUL、非法 UTF-8、控制字符（允许 \n/\r/\t）及 Unicode Cf/Bidi 字符；空串编码为 ””。
func QuotePOSIX(arg string) (string, error) {
	if hasForbiddenCommandText(arg) {
		return "", fmt.Errorf("%w: POSIX 参数包含非法 UTF-8、NUL、控制或 Cf/Bidi 字符", ErrInvalidShellQuote)
	}
	return quotePOSIXTrusted(arg), nil
}

func quotePOSIXTrusted(arg string) string {
	if arg == "" {
		return "''"
	}
	var b strings.Builder
	b.Grow(len(arg) + 2)
	b.WriteByte('\'')
	for i := range len(arg) {
		if arg[i] == '\'' {
			b.WriteString(`'\''`)
			continue
		}
		b.WriteByte(arg[i])
	}
	b.WriteByte('\'')
	return b.String()
}

// QuotePowerShell 使用 PowerShell 单引号字面量规则对参数安全引用。
// 除拒绝 NUL/非法 UTF-8/控制/Cf 字符外，还将 ASCII 单引号与 PowerShell 解析器视作等价引号的
// Unicode 弯引号（U+2018..U+201B）一并拒绝或转义，阻断引号逃逸注入。
func QuotePowerShell(arg string) (string, error) {
	if hasForbiddenCommandText(arg) {
		return "", fmt.Errorf("%w: PowerShell 参数包含非法 UTF-8、NUL、控制或 Cf/Bidi 字符", ErrInvalidShellQuote)
	}
	if strings.ContainsFunc(arg, isPowerShellSmartSingleQuote) {
		return "", fmt.Errorf("%w: PowerShell 单引号字面量拒绝 Unicode 弯单引号以防解析器逃逸", ErrInvalidShellQuote)
	}
	return quotePowerShellTrusted(arg), nil
}

func quotePowerShellTrusted(arg string) string {
	if arg == "" {
		return "''"
	}
	var b strings.Builder
	b.Grow(len(arg) + 2)
	b.WriteByte('\'')
	for i := range len(arg) {
		if arg[i] == '\'' {
			b.WriteString("''")
			continue
		}
		b.WriteByte(arg[i])
	}
	b.WriteByte('\'')
	return b.String()
}

func isPowerShellSmartSingleQuote(r rune) bool {
	return r == '\u2018' || r == '\u2019' || r == '\u201a' || r == '\u201b'
}

// QuoteCmdArg 对 Windows cmd.exe 参数执行保守失败关闭引用。
// 由于 cmd.exe 对换行、%VAR%、!VAR! 与元字符存在不可安全屏蔽的二次展开风险，
// 本函数严格拒绝换行、控制/Cf 字符与危险元字符；当含空白/逗号/分号/等号需加双引号时，
// 同步拒绝尾部反斜杠以防 Win32 CommandLineToArgvW 将 \" 解释为转义引号。
func QuoteCmdArg(arg string) (string, error) {
	if err := validateCmdText(arg, "cmd 参数"); err != nil {
		return "", err
	}
	if arg == "" {
		return `""`, nil
	}
	if !strings.ContainsAny(arg, " \t,;=") {
		return arg, nil
	}
	if strings.HasSuffix(arg, `\`) {
		return "", fmt.Errorf("%w: cmd 双引号参数禁止以反斜杠结尾以防转义闭合引号", ErrInvalidShellQuote)
	}
	return `"` + arg + `"`, nil
}

func validateCmdText(val, label string) error {
	if hasForbiddenStrictText(val) {
		return fmt.Errorf("%w: %s包含非法 UTF-8、控制或 Cf/Bidi 字符", ErrInvalidShellQuote, label)
	}
	if strings.ContainsAny(val, "\"%!^&|<>()\r\n") {
		return fmt.Errorf("%w: %s包含禁止的元字符或变量展开符", ErrInvalidShellQuote, label)
	}
	return nil
}

// EncodePowerShellUTF16LEBase64 将 PowerShell 脚本文本编码为标准 UTF-16LE Base64，
// 供 powershell.exe / pwsh 的 -EncodedCommand 参数安全传递（彻底隔离外层 POSIX/cmd 引号解析）。
func EncodePowerShellUTF16LEBase64(script string) (string, error) {
	if script == "" || hasForbiddenCommandText(script) {
		return "", fmt.Errorf("%w: PowerShell 脚本为空或包含非法 UTF-8/NUL/控制/Cf 字符", ErrInvalidShellQuote)
	}
	units := utf16.Encode([]rune(script))
	raw := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(raw[i*2:], u)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// redactCommandSummary 为命令计划生成单行脱敏展示摘要：
// 绝不输出环境变量值（仅展示键名），对常见内联凭据模式做 [REDACTED] 替换，并清洗控制/Bidi 字符与截断超长正文。
func redactCommandSummary(p CommandPlan) string {
	if !p.IsValid() {
		return "<invalid command plan>"
	}
	var parts []string
	parts = append(parts, fmt.Sprintf("[%s:%s/%s]", p.kind, p.profile.Dialect(), p.profile.Interpreter()))
	if wd, ok := p.workDir.Get(); ok {
		parts = append(parts, "cwd="+security.SanitizePromptText(wd.String()))
	}
	if len(p.env) > 0 {
		keys := make([]string, len(p.env))
		for i, kv := range p.env {
			keys[i] = kv.key
		}
		parts = append(parts, "env=["+strings.Join(keys, ",")+"]")
	}
	if p.pty {
		parts = append(parts, "pty=true")
	}
	body := formatRedactedPayload(p)
	parts = append(parts, body)
	return strings.Join(parts, " ")
}

func formatRedactedPayload(p CommandPlan) string {
	raw := p.command
	if len(p.argv) > 0 {
		raw = strings.Join(p.argv, " ")
	}
	masked := redactInlineSecrets(raw)
	sanitized := security.SanitizePromptText(masked)
	return truncateRunes(sanitized, maxSummaryRunes)
}

func redactInlineSecrets(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); {
		if valStart, valEnd, ok := matchBearerSpan(raw, i); ok {
			b.WriteString(raw[i:valStart])
			b.WriteString("[REDACTED]")
			i = valEnd
			continue
		}
		if valStart, valEnd, ok := matchKVSecretSpan(raw, i); ok {
			b.WriteString(raw[i:valStart])
			b.WriteString("[REDACTED]")
			i = valEnd
			continue
		}
		b.WriteByte(raw[i])
		i++
	}
	return b.String()
}

func isIdentByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

func matchBearerSpan(s string, pos int) (int, int, bool) {
	if pos > 0 && isIdentByte(s[pos-1]) {
		return 0, 0, false
	}
	if len(s)-pos < 7 || !strings.EqualFold(s[pos:pos+6], "bearer") || (s[pos+6] != ' ' && s[pos+6] != '\t') {
		return 0, 0, false
	}
	valStart := skipHorizSpaces(s, pos+6)
	valEnd := scanSecretValueEnd(s, valStart)
	if valEnd == valStart {
		return 0, 0, false
	}
	return valStart, valEnd, true
}

func matchKVSecretSpan(s string, pos int) (int, int, bool) {
	if pos > 0 && isIdentByte(s[pos-1]) {
		return 0, 0, false
	}
	kwLen := matchSensitiveKeywordLen(s[pos:])
	if kwLen == 0 {
		return 0, 0, false
	}
	sepPos := skipHorizSpaces(s, pos+kwLen)
	var valStart int
	switch {
	case sepPos < len(s) && (s[sepPos] == '=' || s[sepPos] == ':'):
		valStart = skipHorizSpaces(s, sepPos+1)
	case pos >= 2 && s[pos-2] == '-' && s[pos-1] == '-' && sepPos > pos+kwLen:
		valStart = sepPos
	default:
		return 0, 0, false
	}
	valEnd := scanSecretValueEnd(s, valStart)
	if valEnd == valStart {
		return 0, 0, false
	}
	return valStart, valEnd, true
}

func matchSensitiveKeywordLen(tail string) int {
	for _, kw := range [...]string{
		"passphrase", "access_key", "access-key", "password",
		"api_key", "api-key", "passwd", "secret", "token", "auth", "pwd",
	} {
		if len(tail) >= len(kw) && strings.EqualFold(tail[:len(kw)], kw) {
			if len(tail) == len(kw) || !isIdentByte(tail[len(kw)]) {
				return len(kw)
			}
		}
	}
	return 0
}

func skipHorizSpaces(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

func scanSecretValueEnd(s string, start int) int {
	if start >= len(s) {
		return start
	}
	if q := s[start]; q == '\'' || q == '"' {
		if end := strings.IndexByte(s[start+1:], q); end >= 0 {
			return start + 1 + end + 1
		}
	}
	i := start
	for i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != '\n' && s[i] != '\r' {
		i++
	}
	return i
}

func truncateRunes(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[:maxRunes]) + "..."
}
