package clikit

import (
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/engine"
)

// CommonFlags 聚合所有命令统一支持的跨命令选项（--json / --policy / -F / -h）。
type CommonFlags struct {
	JSON       bool
	Policy     engine.PolicyProfile
	ConfigFile string
	ShowHelp   bool
}

// FlagCursor 提供零全局状态的轻量命令行参数游标，支持长选项（--k v / --k=v）、短选项与 `--` 终止符。
type FlagCursor struct {
	args []string
	idx  int
}

// NewFlagCursor 创建指向 args 起始位置的参数游标。
func NewFlagCursor(args []string) *FlagCursor {
	return &FlagCursor{args: args}
}

// HasNext 报告游标是否仍有未消耗参数。
func (c *FlagCursor) HasNext() bool { return c.idx < len(c.args) }

// Peek 返回当前游标指向的原始参数而不推进游标。
func (c *FlagCursor) Peek() string { return c.args[c.idx] }

// Next 读取并推进一个原始参数。
func (c *FlagCursor) Next() string {
	v := c.args[c.idx]
	c.idx++
	return v
}

// Rest 返回尚未消耗的剩余参数切片副本。
func (c *FlagCursor) Rest() []string {
	if c.idx >= len(c.args) {
		return nil
	}
	return append([]string(nil), c.args[c.idx:]...)
}

// ConsumeShortArg 按 OpenSSH 习惯读取短选项参数值（优先消费紧贴余串，否则读取下一位置参数）。
func (c *FlagCursor) ConsumeShortArg(flagChar byte, remainder string) (string, error) {
	if remainder != "" {
		return remainder, nil
	}
	if !c.HasNext() {
		return "", fmt.Errorf("%w: 选项 -%c 缺少参数值", ErrUsage, flagChar)
	}
	return c.Next(), nil
}

// SplitLongFlag 将 `--name` 或 `--name=value` 拆分为 (name, value, hasInlineValue)。
func SplitLongFlag(raw string) (name, val string, hasEq bool) {
	body := strings.TrimPrefix(raw, "--")
	if k, v, ok := strings.Cut(body, "="); ok {
		return k, v, true
	}
	return body, "", false
}

// ParseLongFlagName 严格校验 raw 以 `--` 开头且名称非空后拆分 (name, val, hasEq, isLong)；
// 拒绝把裸位置词或单横线选项误判为长选项。
func ParseLongFlagName(raw string) (name, val string, hasEq, isLong bool) {
	if !strings.HasPrefix(raw, "--") || len(raw) <= 2 {
		return "", "", false, false
	}
	name, val, hasEq = SplitLongFlag(raw)
	if name == "" {
		return "", "", false, false
	}
	return name, val, hasEq, true
}

// HasJSONFlag 预扫描参数（遇到 `--` 即止）判断是否声明了 `--json`（兼容 `--json=true/false` 末次生效），
// 确保任何子命令在参数语法报错时仍能稳定输出规范 JSON ErrorEnvelope。
func HasJSONFlag(args []string) bool {
	enabled := false
	for _, tok := range args {
		if tok == "--" {
			break
		}
		name, inlineVal, hasEq, isLong := ParseLongFlagName(tok)
		if !isLong || name != "json" {
			continue
		}
		if !hasEq {
			enabled = true
			continue
		}
		switch strings.ToLower(strings.TrimSpace(inlineVal)) {
		case "true", "1", "t", "yes":
			enabled = true
		case "false", "0", "f", "no":
			enabled = false
		}
	}
	return enabled
}

// ConsumeLongValue 读取长选项值：已携带 `=value` 时直接返回，否则消耗下一参数（缺失则返 ErrUsage）。
func (c *FlagCursor) ConsumeLongValue(name, inlineVal string, hasEq bool) (string, error) {
	if hasEq {
		return inlineVal, nil
	}
	if !c.HasNext() {
		return "", fmt.Errorf("%w: 选项 --%s 缺少参数值", ErrUsage, name)
	}
	return c.Next(), nil
}

// ParseGlobalPrefix 解析出现在子命令之前的全局前置标志（--json / --policy / -F / -h / --help / -V / --version）。
// 遇到首个子命令词时立即停止，返回剩余参数切片。
func ParseGlobalPrefix(args []string) (CommonFlags, []string, error) {
	var cf CommonFlags
	cur := NewFlagCursor(args)
	for cur.HasNext() {
		tok := cur.Peek()
		if tok == "--" {
			cur.Next()
			break
		}
		if !strings.HasPrefix(tok, "-") || tok == "-" {
			break
		}
		if tok == "-V" || tok == "--version" || tok == "-h" || tok == "--help" {
			break
		}
		consumed, err := consumeGlobalPrefixToken(cur, &cf)
		if err != nil {
			cf.JSON = cf.JSON || HasJSONFlag(args)
			return cf, nil, err
		}
		if !consumed {
			break
		}
	}
	return cf, cur.Rest(), nil
}

func consumeGlobalPrefixToken(cur *FlagCursor, cf *CommonFlags) (bool, error) {
	tok := cur.Peek()
	if strings.HasPrefix(tok, "--") {
		return TryConsumeCommonLongFlag(cur, cf)
	}
	if tok == "-F" || strings.HasPrefix(tok, "-F") {
		cur.Next()
		val, err := cur.ConsumeShortArg('F', tok[2:])
		if err != nil {
			return false, err
		}
		if err := SetConfigFile(&cf.ConfigFile, val); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// TryConsumeCommonLongFlag 尝试解析统一长选项（--json / --policy / --ssh-config / --help）。
// 若当前 token 匹配则消耗并更新 cf 返回 (true, nil)；不匹配返回 (false, nil) 不推进游标。
func TryConsumeCommonLongFlag(cur *FlagCursor, cf *CommonFlags) (bool, error) {
	tok := cur.Peek()
	if !strings.HasPrefix(tok, "--") || tok == "--" {
		return false, nil
	}
	name, inlineVal, hasEq := SplitLongFlag(tok)
	switch name {
	case "help":
		cur.Next()
		if hasEq {
			return false, fmt.Errorf("%w: --help 不接受参数值", ErrUsage)
		}
		cf.ShowHelp = true
		return true, nil
	case "json":
		cur.Next()
		v, err := ParseOptionalBool(name, inlineVal, hasEq)
		if err != nil {
			return false, err
		}
		cf.JSON = v
		return true, nil
	case "policy":
		cur.Next()
		raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		if err != nil {
			return false, err
		}
		p, err := engine.ParsePolicyProfile(raw)
		if err != nil {
			return false, fmt.Errorf("%w: --policy 参数 %q 非法: %w", ErrUsage, raw, err)
		}
		cf.Policy = p
		return true, nil
	case "ssh-config":
		cur.Next()
		raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		if err != nil {
			return false, err
		}
		return true, SetConfigFile(&cf.ConfigFile, raw)
	default:
		return false, nil
	}
}

// SetConfigFile 校验并写入 OpenSSH `-F` 配置文件覆写路径（拒绝纯空白字符串）。
func SetConfigFile(dst *string, raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("%w: -F 配置文件路径不能为空", ErrUsage)
	}
	*dst = raw
	return nil
}

// ParseOptionalBool 解析布尔标志（无 `=value` 默认 true；有 `=value` 仅接受 true/false）。
func ParseOptionalBool(name, inlineVal string, hasEq bool) (bool, error) {
	if !hasEq {
		return true, nil
	}
	switch strings.ToLower(strings.TrimSpace(inlineVal)) {
	case "true", "1", "yes":
		return true, nil
	case "false", "0", "no":
		return false, nil
	default:
		return false, fmt.Errorf("%w: 布尔选项 --%s 参数 %q 非法", ErrUsage, name, inlineVal)
	}
}

// ParsePositiveInt 解析严格正整数参数。
func ParsePositiveInt(flagName, raw string) (int, error) {
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("%w: %s 需要正整数，实际=%q", ErrUsage, flagName, raw)
	}
	return v, nil
}

// ParseNonNegInt64 解析非负 64 位整数参数。
func ParseNonNegInt64(flagName, raw string) (int64, error) {
	v, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("%w: %s 需要非负整数，实际=%q", ErrUsage, flagName, raw)
	}
	return v, nil
}

// ParseNonNegUint64 解析非负无符号 64 位整数参数。
func ParseNonNegUint64(flagName, raw string) (uint64, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %s 需要非负整数，实际=%q", ErrUsage, flagName, raw)
	}
	return v, nil
}

// ParsePositiveDuration 解析严格正时长（返回 algebraic.Duration，杜绝裸 time.Duration 混入 DTO）。
func ParsePositiveDuration(flagName, raw string) (algebraic.Duration, error) {
	d, err := algebraic.ParseDuration(strings.TrimSpace(raw))
	if err != nil || !d.IsPositive() {
		return algebraic.ZeroDuration(), fmt.Errorf("%w: %s 需要正时长（如 30s、5m），实际=%q", ErrUsage, flagName, raw)
	}
	return d, nil
}

// ParseOctalPerm 解析标准 POSIX 八进制文件权限位（0001..0777，与 transfer 用例 resolvePerm 保持一致）。
func ParseOctalPerm(flagName, raw string) (fs.FileMode, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, fmt.Errorf("%w: %s 权限不能为空", ErrUsage, flagName)
	}
	v, err := strconv.ParseUint(trimmed, 8, 32)
	if err != nil || v == 0 || v > 0o777 {
		return 0, fmt.Errorf("%w: %s 需要合法八进制权限位（0001..0777），实际=%q", ErrUsage, flagName, raw)
	}
	return fs.FileMode(v), nil
}

// ParseKeyValue 拆分 KEY=VALUE 形式的环境变量或变量赋值参数。
func ParseKeyValue(flagName, raw string) (key, val string, err error) {
	k, v, ok := strings.Cut(raw, "=")
	if !ok || strings.TrimSpace(k) == "" {
		return "", "", fmt.Errorf("%w: %s 需要 KEY=VALUE 格式，实际=%q", ErrUsage, flagName, raw)
	}
	return k, v, nil
}

// SplitCSV 拆分逗号分隔非空条目（去除首尾空白并忽略空元素）。
func SplitCSV(raw string) []string {
	var out []string
	for part := range strings.SplitSeq(raw, ",") {
		if s := strings.TrimSpace(part); s != "" {
			out = append(out, s)
		}
	}
	return out
}
