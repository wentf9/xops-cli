// Package execution 提供 XOps v2 纯函数领域核的命令执行计划、多方言安全引用与执行结果代数和类型。
//
// 本包恪守 100% 纯数学与零副作用铁律（零 os、零 net、零 context、零 sync/sync/atomic、零反射）：
//   - LaunchProfile / LaunchDialect / Interpreter / LoginMode：显式区分服务端直通（server）与
//     受控解释器（sh/bash/zsh/powershell/pwsh/cmd），以及登录模式与 POSIX Bourne 强校验（INV-E4）；
//   - CommandPlan：不可变命令/脚本执行计划，承载工作目录（pathalg.RemotePath）、环境变量校验、
//     algebraic.Duration 超时、输出上限、零反射 //xops:canonicalhash 规范摘要、多方言无 OS 引用渲染与脱敏摘要；
//   - ExecutionOutcome 与 ExitStatus：封闭代数和类型（RFC §3.6），严格保证仅有效 *OutcomeNotStarted
//     允许重试（CanRetry() == true），*OutcomeCompleted 与 *OutcomeUnknown 及零值/nil 恒不可重试。
package execution

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/security"
)

const (
	// DefaultMaxOutputBytes 表示未显式指定输出上限时的默认命令输出截断上限（4 MiB）。
	DefaultMaxOutputBytes uint64 = 4 << 20
	// MaxAllowedOutputBytes 表示单次命令计划允许配置的最大输出上限（64 MiB）。
	MaxAllowedOutputBytes uint64 = 64 << 20

	maxCommandBytes            = 1 << 20 // 单条命令或脚本文本上限（1 MiB）
	maxWindowsCommandLineChars = 32767   // Windows CreateProcessW 命令行 UTF-16 字符上限
	maxArgvCount               = 1024
	maxArgBytes                = 64 << 10
	maxEnvCount                = 256
	maxEnvKeyLen               = 256
	maxEnvValBytes             = 64 << 10
	maxSignalNameLen           = 32
	maxCodeLen                 = 128
	maxSummaryRunes            = 120
)

// 本包导出的规范哨兵错误，所有非法组合、越界输入、JSON null 及零值调用均严格失败关闭。
var (
	ErrInvalidLaunchDialect            = errors.New("execution: 无效的启动方言 LaunchDialect")
	ErrInvalidInterpreter              = errors.New("execution: 无效的解释器 Interpreter")
	ErrInvalidLoginMode                = errors.New("execution: 无效的登录模式 LoginMode")
	ErrInvalidLaunchProfile            = errors.New("execution: 无效的启动配置 LaunchProfile")
	ErrUnsupportedExecutionCombination = errors.New("execution: 不支持的启动方言、解释器、登录模式或工作目录组合")
	ErrNotPOSIXBourne                  = errors.New("execution: 当前启动配置不满足 POSIX Bourne 解释器要求")
	ErrInvalidPlanKind                 = errors.New("execution: 无效的计划类型 PlanKind")
	ErrInvalidCommandPlan              = errors.New("execution: 无效的命令执行计划 CommandPlan")
	ErrInvalidEnvVar                   = errors.New("execution: 无效的环境变量键值")
	ErrInvalidShellQuote               = errors.New("execution: 无法对包含非法控制字符或不可转义序列的文本进行安全引用")
	ErrInvalidPhase                    = errors.New("execution: 无效的执行阶段枚举")
	ErrInvalidExitStatus               = errors.New("execution: 无效的退出状态 ExitStatus")
	ErrInvalidExecutionOutcome         = errors.New("execution: 无效的执行结果 ExecutionOutcome")
	ErrNilWriter                       = errors.New("execution: WriteCanonical 或编码目标不能为 nil")
	ErrNilReceiver                     = errors.New("execution: 反序列化目标接收者不能为 nil")
)

func pickIf[T any](ok bool, yes, no T) T {
	if ok {
		return yes
	}
	return no
}

func enumName(idx uint8, fallback string, names ...string) string {
	if int(idx) < len(names) {
		return names[idx]
	}
	return fallback
}

func appendValidText(b []byte, valid bool, text string, baseErr error, raw uint8) ([]byte, error) {
	if !valid {
		return nil, fmt.Errorf("%w: %d", baseErr, raw)
	}
	return append(b, text...), nil
}

func unmarshalTextWithReset[T any](dst *T, zero T, text []byte, parse func(string) (T, error)) error {
	if dst == nil {
		return ErrNilReceiver
	}
	parsed, err := parse(string(text))
	if err != nil {
		*dst = zero
		return err
	}
	*dst = parsed
	return nil
}

// rejectJSONNull 拦截顶层 JSON null 并透传畸形前缀（如 "nul"）的语法错误。
func rejectJSONNull(dec *jsontext.Decoder, baseErr error) (bool, error) {
	if dec.PeekKind() != 'n' {
		return false, nil
	}
	if _, err := dec.ReadToken(); err != nil {
		return true, err
	}
	return true, fmt.Errorf("%w: JSON null 不是有效值", baseErr)
}

func unmarshalJSONWithNullReject[T, W any](dst *T, dec *jsontext.Decoder, baseErr error, build func(W) (T, error)) error {
	if dst == nil || dec == nil {
		return ErrNilReceiver
	}
	var zero T
	*dst = zero
	if isNull, err := rejectJSONNull(dec, baseErr); isNull {
		return err
	}
	var wire W
	if err := jsonv2.UnmarshalDecode(dec, &wire); err != nil {
		return err
	}
	parsed, err := build(wire)
	if err != nil {
		return err
	}
	*dst = parsed
	return nil
}

// isForbiddenStrictRune 判定单行标识、环境变量值与参数中禁止出现的控制与 Unicode Cf/Bidi 字符。
func isForbiddenStrictRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
}

func hasForbiddenStrictText(s string) bool {
	return !utf8.ValidString(s) || strings.ContainsFunc(s, isForbiddenStrictRune)
}

// isForbiddenCommandRune 判定命令/脚本正文中禁止出现的字符（允许 \n/\r/\t，严禁 NUL、其余控制字符与 Cf/Bidi）。
func isForbiddenCommandRune(r rune) bool {
	if r == '\n' || r == '\r' || r == '\t' {
		return false
	}
	return isForbiddenStrictRune(r)
}

func hasForbiddenCommandText(s string) bool {
	return !utf8.ValidString(s) || strings.IndexByte(s, 0) >= 0 || strings.ContainsFunc(s, isForbiddenCommandRune)
}

func isValidEnvKey(k string) bool {
	if len(k) == 0 || len(k) > maxEnvKeyLen || !utf8.ValidString(k) {
		return false
	}
	for i := range len(k) {
		c := k[i]
		isLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
		isDigit := c >= '0' && c <= '9'
		if (i == 0 && !isLetter) || (i > 0 && !isLetter && !isDigit) {
			return false
		}
	}
	return true
}

func isValidASCIICode(s string, maxLen int) bool {
	if len(s) == 0 || len(s) > maxLen {
		return false
	}
	for i := range len(s) {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == ':'
		if !ok {
			return false
		}
	}
	return true
}

// canonicalEncoder 提供零反射、带显式长度前缀与域分离标签的规范摘要写入器。
type canonicalEncoder struct {
	w   io.Writer
	err error
}

func digestCanonical(writeFn func(io.Writer) error) (security.Digest, error) {
	h := sha256.New()
	if err := writeFn(h); err != nil {
		var zero security.Digest
		return zero, err
	}
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return security.DigestFromSHA256(sum), nil
}

func (e *canonicalEncoder) fail(err error) {
	if err != nil && e.err == nil {
		e.err = err
	}
}

func (e *canonicalEncoder) writeRaw(p []byte) {
	if e.err == nil && len(p) > 0 {
		_, e.err = e.w.Write(p)
	}
}

func (e *canonicalEncoder) writeUint8(v uint8) { e.writeRaw([]byte{v}) }
func (e *canonicalEncoder) writeBool(v bool)   { e.writeUint8(pickIf[uint8](v, 1, 0)) }
func (e *canonicalEncoder) writeInt64(v int64) { e.writeUint64(uint64(v)) }
func (e *canonicalEncoder) writeUint64(v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	e.writeRaw(buf[:])
}

func (e *canonicalEncoder) writeString(s string) {
	e.writeUint64(uint64(len(s)))
	e.writeRaw([]byte(s))
}

func (e *canonicalEncoder) writeStrings(items []string) {
	e.writeUint64(uint64(len(items)))
	for _, item := range items {
		e.writeString(item)
	}
}
