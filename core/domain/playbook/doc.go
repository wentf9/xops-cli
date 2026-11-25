// Package playbook 提供 XOps v2 纯函数领域核的判别式 Playbook vNext AST、
// 封闭步骤动作代数和类型（StepAction）与顺序无关纯报表折叠（FoldPlaybookReport）。
//
// 本包恪守 100% 纯数学与零副作用铁律（零 os、零 net、零 context、零 sync/sync/atomic、零反射），
// 严格遵循 ADR-006（仅支持 version: 2，100% 零 v1 兼容代码）与 ADR-013/ADR-014 封装不变式：
//   - Playbook：不可变声明式执行快照，经 //xops:canonicalhash 由 xopsvet/digestcover 校验全字段覆盖，
//     在 Go 1.27 encoding/json/v2 下支持 Deterministic(true) 往返并严格拒绝 null、缺失字段与未知字段；
//   - StepAction：封闭和类型（*StepShell | *StepScript | *StepCopy | *StepTemplate | *StepEnsure），
//     其中 *StepEnsure 严格禁止嵌套 *StepEnsure 以锁死递归深度上限；
//   - FoldPlaybookReport：纯确定性折叠，节点间按 NodeID 排序实现输入置换不变性，节点内严格保序，
//     绝不将 execution.OutcomeUnknown 降级为可重试或成功状态。
package playbook

import (
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/security"
)

const (
	// VersionV2 表示 XOps v2 Playbook 唯一受支持的规范 Schema 版本号（严禁 v1 兼容）。
	VersionV2 uint32 = 2
	// MaxEnsureRetries 表示 StepEnsure 针对可证明未启动（OutcomeNotStarted）的最大允许重试次数上限。
	MaxEnsureRetries uint8 = 10

	maxIDLen, maxNameBytes, maxDescriptionBytes = 128, 256, 1024
	maxCommandBytes, maxArgsCount, maxArgBytes  = 1 << 20, 1024, 64 << 10
	maxEnvCount, maxEnvKeyLen, maxEnvValBytes   = 256, 256, 64 << 10
	maxVarsCount, maxVarKeyLen, maxVarValBytes  = 256, 128, 64 << 10
	maxStepsPerPlaybook, maxSelectorItems       = 256, 1024
	maxStepTags, maxFileMode, maxMessageBytes   = 64, 0o7777, 1024
	forbiddenIDChars                            = "@:/\\,;|$`<>(){}!'\"*?[]"
)

// 本包导出的规范哨兵错误，所有非法字段、v1 版本、嵌套 ensure、重复步骤、JSON null/未知字段及零值调用均失败关闭。
var (
	ErrUnsupportedVersion    = errors.New("playbook: 不支持的 Playbook Schema 版本（仅接受 version=2）")
	ErrInvalidPlaybookID     = errors.New("playbook: 无效的 PlaybookID")
	ErrInvalidStepID         = errors.New("playbook: 无效的 StepID")
	ErrInvalidOnErrorPolicy  = errors.New("playbook: 无效的 OnErrorPolicy")
	ErrInvalidFileMode       = errors.New("playbook: 无效的 POSIX FileMode")
	ErrInvalidTargetSelector = errors.New("playbook: 无效的目标节点选择器 TargetSelector")
	ErrInvalidStepAction     = errors.New("playbook: 无效的步骤动作 StepAction")
	ErrInvalidEnsureCheck    = errors.New("playbook: StepEnsure.Check 仅允许只读探测动作（shell 或 script）")
	ErrNestedEnsureForbidden = errors.New("playbook: 禁止在 StepEnsure 内部嵌套 StepEnsure")
	ErrInvalidStep           = errors.New("playbook: 无效的步骤定义 Step")
	ErrDuplicateStepID       = errors.New("playbook: Playbook 中存在重复的 StepID")
	ErrInvalidPlaybook       = errors.New("playbook: 无效的 Playbook 定义")
	ErrTamperedDigest        = errors.New("playbook: 编码携带的 Playbook 规范摘要与重算结果不匹配")
	ErrInvalidVar            = errors.New("playbook: 无效的环境变量或模板变量键值")
	ErrInvalidStepStatus     = errors.New("playbook: 无效的步骤执行状态 StepStatus")
	ErrInvalidNodeStatus     = errors.New("playbook: 无效的节点汇总状态 NodeStatus")
	ErrInvalidStepRecord     = errors.New("playbook: 无效的步骤执行记录 StepExecutionRecord")
	ErrOutcomeStatusMismatch = errors.New("playbook: ExecutionOutcome 与 StepStatus 语义冲突（严禁降级 OutcomeUnknown）")
	ErrDuplicateStepRecord   = errors.New("playbook: 同一节点的同一步骤存在重复执行记录")
	ErrUnknownStepID         = errors.New("playbook: 执行记录引用了不在 Playbook 中的 StepID")
	ErrEmptyReport           = errors.New("playbook: 执行记录列表为空，无法生成 PlaybookReport")
	ErrNilWriter             = errors.New("playbook: WriteCanonical 或编码目标不能为 nil")
	ErrNilReceiver           = errors.New("playbook: 反序列化目标接收者不能为 nil")
)

type kvEntry struct{ key, value string }

func zeroVal[T any]() (z T) { return z }

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

func parseEnumByName[T ~uint8](raw string, lo, hi, zero T, nameFn func(T) string, baseErr error) (T, error) {
	if !hasForbiddenStrictText(raw) {
		for norm, v := strings.ToLower(strings.TrimSpace(raw)), lo; v <= hi; v++ {
			if nameFn(v) == norm {
				return v, nil
			}
		}
	}
	return zero, fmt.Errorf("%w: %q", baseErr, raw)
}

func appendValidText(b []byte, valid bool, text string, baseErr error) ([]byte, error) {
	if !valid {
		return nil, baseErr
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

// unmarshalJSONStrict 统一实现失败关闭的 JSON/v2 解码：重置零值、拦截顶层 null、开启 RejectUnknownMembers(true)。
func unmarshalJSONStrict[T, W any](dst *T, dec *jsontext.Decoder, baseErr error, build func(W) (T, error)) error {
	if dst == nil || dec == nil {
		return ErrNilReceiver
	}
	*dst = zeroVal[T]()
	if dec.PeekKind() == 'n' {
		if _, err := dec.ReadToken(); err != nil {
			return err
		}
		return fmt.Errorf("%w: JSON null 不是有效值", baseErr)
	}
	var wire W
	if err := jsonv2.UnmarshalDecode(dec, &wire, jsonv2.RejectUnknownMembers(true)); err != nil {
		return err
	}
	parsed, err := build(wire)
	if err == nil {
		*dst = parsed
	}
	return err
}

func maskFlags(flags ...bool) uint16 {
	var m uint16
	for i, f := range flags {
		if f {
			m |= 1 << i
		}
	}
	return m
}

func equalOptionFunc[T any](a, b algebraic.Option[T], eq func(T, T) bool) bool {
	va, oka := a.Get()
	vb, okb := b.Get()
	return oka == okb && (!oka || eq(va, vb))
}

func isForbiddenStrictRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
}
func hasForbiddenStrictText(s string) bool {
	return !utf8.ValidString(s) || strings.ContainsFunc(s, isForbiddenStrictRune)
}
func hasSpaceOrForbidden(s string) bool {
	return hasForbiddenStrictText(s) || strings.ContainsFunc(s, unicode.IsSpace)
}
func hasForbiddenCommandText(s string) bool {
	return !utf8.ValidString(s) || strings.IndexByte(s, 0) >= 0 || strings.ContainsFunc(s, func(r rune) bool {
		return r != '\n' && r != '\r' && r != '\t' && isForbiddenStrictRune(r)
	})
}
func hasVisibleText(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return !unicode.IsSpace(r) })
}

// truncateUTF8 在不超过 maxBytes 字节的前提下沿合法 UTF-8 字符边界截断字符串，避免切碎多字节符文。
func truncateUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func validateIdentToken(raw string, baseErr error) error {
	if raw == "" || len(raw) > maxIDLen || hasSpaceOrForbidden(raw) || raw == "." || raw == ".." || raw[0] == '-' || strings.ContainsAny(raw, forbiddenIDChars) {
		return fmt.Errorf("%w: %q 格式非法", baseErr, raw)
	}
	return nil
}

func isValidEnvKey(k string) bool { return isValidKey(k, maxEnvKeyLen, false) }
func isValidVarKey(k string) bool { return isValidKey(k, maxVarKeyLen, true) }

func isKeyStartByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}

func isKeyBodyByte(c byte, allowDashDot bool) bool {
	return isKeyStartByte(c) || (c >= '0' && c <= '9') || (allowDashDot && (c == '-' || c == '.'))
}

func isValidKey(k string, maxLen int, allowDashDot bool) bool {
	if len(k) == 0 || len(k) > maxLen || !isKeyStartByte(k[0]) {
		return false
	}
	for i := 1; i < len(k); i++ {
		if !isKeyBodyByte(k[i], allowDashDot) {
			return false
		}
	}
	return true
}

func canonicalizeKVMap(raw map[string]string, maxCount, maxValBytes int, keyOK func(string) bool, allowMultiline bool) ([]kvEntry, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > maxCount {
		return nil, fmt.Errorf("%w: 条目数 %d 超过上限 %d", ErrInvalidVar, len(raw), maxCount)
	}
	out := make([]kvEntry, 0, len(raw))
	for _, k := range slices.Sorted(maps.Keys(raw)) {
		v := raw[k]
		if !keyOK(k) || len(v) > maxValBytes || pickIf(allowMultiline, hasForbiddenCommandText(v), hasForbiddenStrictText(v)) {
			return nil, fmt.Errorf("%w: 非法键值 %q", ErrInvalidVar, k)
		}
		out = append(out, kvEntry{key: k, value: v})
	}
	return out, nil
}

func kvSliceToMap(entries []kvEntry) map[string]string {
	if len(entries) == 0 {
		return nil
	}
	out := make(map[string]string, len(entries))
	for _, kv := range entries {
		out[kv.key] = kv.value
	}
	return out
}

func lookupKV(entries []kvEntry, key string) (string, bool) {
	if idx, ok := slices.BinarySearchFunc(entries, key, func(item kvEntry, target string) int { return cmp.Compare(item.key, target) }); ok {
		return entries[idx].value, true
	}
	return "", false
}

type canonicalEncoder struct {
	w   io.Writer
	err error
}

func digestCanonical(writeFn func(io.Writer) error) (security.Digest, error) {
	h := sha256.New()
	if err := writeFn(h); err != nil {
		return zeroVal[security.Digest](), err
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
func (e *canonicalEncoder) writeUint8(v uint8)   { e.writeRaw([]byte{v}) }
func (e *canonicalEncoder) writeBool(v bool)     { e.writeUint8(pickIf[uint8](v, 1, 0)) }
func (e *canonicalEncoder) writeUint32(v uint32) { e.writeUint64(uint64(v)) }
func (e *canonicalEncoder) writeInt64(v int64)   { e.writeUint64(uint64(v)) }
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
	for _, s := range items {
		e.writeString(s)
	}
}
func (e *canonicalEncoder) writeKVs(entries []kvEntry) {
	e.writeUint64(uint64(len(entries)))
	for _, kv := range entries {
		e.writeString(kv.key)
		e.writeString(kv.value)
	}
}
func writeStringers[T fmt.Stringer](e *canonicalEncoder, items []T) {
	e.writeUint64(uint64(len(items)))
	for _, x := range items {
		e.writeString(x.String())
	}
}
