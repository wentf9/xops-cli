// Package ports 定义 XOps v2 六边形核心的全部出站端口契约（公开契约 2，ADR-002 / ADR-003）。
//
// 本包仅允许依赖 core/domain/** 与受控标准库，严禁引入 core/internal/**、core/osfs、core/conc、
// core/events、testing 或具体协议实现库；全作用域闭包（//xops:syncclosure + //xops:borrowed）、
// 双模态本地 FS 隔离（ScopedRootFS vs OperatorReadFS）、失败关闭零值与严格 json/v2 编解码均由本包确立。
package ports

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

const maxPortTokenLen, maxPortDetailBytes, maxPortEnvCount, maxPortEnvValBytes = 128, 512, 256, 8192

// 本包导出的规范化哨兵错误，供用例、连接池、能力门控、宿主适配器、仿真器与 TCK 统一以 errors.Is 判定。
var (
	// 通用契约与参数错误。
	ErrNilContext       = domi18n.Sentinel(domi18n.KeyPortsNilContext)
	ErrNilCallback      = domi18n.Sentinel(domi18n.KeyPortsNilCallback)
	ErrNilReceiver      = domi18n.Sentinel(domi18n.KeyPortsNilReceiver)
	ErrInvalidArgument  = domi18n.Sentinel(domi18n.KeyPortsInvalidArgument)
	ErrUnsupported      = domi18n.Sentinel(domi18n.KeyPortsUnsupported)
	ErrClosed           = domi18n.Sentinel(domi18n.KeyPortsClosed)
	ErrNotFound         = domi18n.Sentinel(domi18n.KeyPortsNotFound)
	ErrAlreadyExists    = domi18n.Sentinel(domi18n.KeyPortsAlreadyExists)
	ErrPermissionDenied = domi18n.Sentinel(domi18n.KeyPortsPermissionDenied)
	ErrLimitExceeded    = domi18n.Sentinel(domi18n.KeyPortsLimitExceeded)
	// 配置存储、CAS 与持久化结果错误。
	ErrRevisionConflict  = domi18n.Sentinel(domi18n.KeyPortsRevisionConflict)
	ErrCorruptData       = domi18n.Sentinel(domi18n.KeyPortsCorruptData)
	ErrInvalidRevision   = domi18n.Sentinel(domi18n.KeyPortsInvalidRevision)
	ErrInvalidDurability = domi18n.Sentinel(domi18n.KeyPortsInvalidDurability)
	// 本地双模态文件系统与文件锁错误。
	ErrInvalidLockMode   = domi18n.Sentinel(domi18n.KeyPortsInvalidLockMode)
	ErrInvalidReadLimits = domi18n.Sentinel(domi18n.KeyPortsInvalidReadLimits)
	ErrLockBusy          = domi18n.Sentinel(domi18n.KeyPortsLockBusy)
	ErrNotRegularFile    = domi18n.Sentinel(domi18n.KeyPortsNotRegularFile)
	ErrSymlinkRejected   = domi18n.Sentinel(domi18n.KeyPortsSymlinkRejected)
	ErrHandleExpired     = domi18n.Sentinel(domi18n.KeyPortsHandleExpired)
	// 凭据库、签名器与主机密钥信任错误。
	ErrVaultLocked        = domi18n.Sentinel(domi18n.KeyPortsVaultLocked)
	ErrSecretNotFound     = domi18n.Sentinel(domi18n.KeyPortsSecretNotFound)
	ErrSecretVerifyFailed = domi18n.Sentinel(domi18n.KeyPortsSecretVerifyFailed)
	ErrHostKeyMismatch    = domi18n.Sentinel(domi18n.KeyPortsHostKeyMismatch)
	ErrHostKeyUnknown     = domi18n.Sentinel(domi18n.KeyPortsHostKeyUnknown)
	ErrHostKeyRevoked     = domi18n.Sentinel(domi18n.KeyPortsHostKeyRevoked)
	ErrSignerUnavailable  = domi18n.Sentinel(domi18n.KeyPortsSignerUnavailable)
	// 传输拨号、多路复用与远端 SFTP 错误。
	ErrDialFailed           = domi18n.Sentinel(domi18n.KeyPortsDialFailed)
	ErrAuthFailed           = domi18n.Sentinel(domi18n.KeyPortsAuthFailed)
	ErrMuxUnavailable       = domi18n.Sentinel(domi18n.KeyPortsMuxUnavailable)
	ErrRemoteAnchorMismatch = domi18n.Sentinel(domi18n.KeyPortsRemoteAnchorMismatch)
	ErrRemoteIsDir          = domi18n.Sentinel(domi18n.KeyPortsRemoteIsDir)
	// 安全审计、崩溃对账、系统与交互错误。
	ErrAuditWriteFailed         = domi18n.Sentinel(domi18n.KeyPortsAuditWriteFailed)
	ErrAuditPostWrite           = domi18n.Sentinel(domi18n.KeyPortsAuditPostWrite)
	ErrAuditHalted              = domi18n.Sentinel(domi18n.KeyPortsAuditHalted)
	ErrInvalidAuditEntry        = domi18n.Sentinel(domi18n.KeyPortsInvalidAuditEntry)
	ErrInvalidProcessInstanceID = domi18n.Sentinel(domi18n.KeyPortsInvalidProcInstID)
	ErrInteractionUnavailable   = domi18n.Sentinel(domi18n.KeyPortsInteractionUnavail)
	ErrInteractionCanceled      = domi18n.Sentinel(domi18n.KeyPortsInteractionCanceled)
	ErrEntropyShortRead         = domi18n.Sentinel(domi18n.KeyPortsEntropyShortRead)
	ErrInvalidTTYSize           = domi18n.Sentinel(domi18n.KeyPortsInvalidTTYSize)
)

func fieldErr(sentinel error, field string) error {
	return domi18n.EF(sentinel, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", field))
}

func pickIf[T any](ok bool, yes, no T) T {
	if ok {
		return yes
	}
	return no
}
func zeroVal[T any]() (z T)                     { return z }
func orZero[T any](ok bool, v T) T              { return pickIf(ok, v, zeroVal[T]()) }
func cloneSliceNilIfEmpty[S ~[]E, E any](s S) S { return pickIf(len(s) == 0, nil, slices.Clone(s)) }
func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
func optEqualFunc[T any](a, b algebraic.Option[T], eq func(T, T) bool) bool {
	va, okA := a.Get()
	vb, okB := b.Get()
	return okA == okB && (!okA || eq(va, vb))
}
func appendValidText(b []byte, ok bool, text string, err error) ([]byte, error) {
	return pickIf(ok, append(b, text...), nil), pickIf[error](ok, nil, err)
}
func unmarshalTextWithReset[T any](dst *T, zero T, text []byte, parse func(string) (T, error)) error {
	if dst == nil {
		return ErrNilReceiver
	}
	parsed, err := parse(string(text))
	*dst = pickIf(err == nil, parsed, zero)
	return err
}

// unmarshalJSONWithNullReject 统一执行失败关闭的 JSON/v2 反序列化：重置零值、拒绝 null 与未知字段并交由构造器核验。
func unmarshalJSONWithNullReject[T, W any](dst *T, dec *jsontext.Decoder, baseErr error, build func(W) (T, error)) error {
	if dst == nil || dec == nil {
		return ErrNilReceiver
	}
	*dst = zeroVal[T]()
	if dec.PeekKind() == 'n' {
		_, err := dec.ReadToken()
		return firstErr(err, domi18n.EF(baseErr, domi18n.KeyCommonJSONNullForbidden))
	}
	var wire W
	if err := jsonv2.UnmarshalDecode(dec, &wire, jsonv2.RejectUnknownMembers(true)); err != nil {
		return err
	}
	parsed, err := build(wire)
	*dst = pickIf(err == nil, parsed, zeroVal[T]())
	return err
}
func marshalValidJSON[W any](enc *jsontext.Encoder, valid bool, badErr error, wire W) error {
	if enc == nil {
		return domi18n.EF(ErrInvalidArgument, domi18n.KeyCommonFieldNil, domi18n.Str("field", "encoder"))
	}
	if !valid {
		return badErr
	}
	return jsonv2.MarshalEncode(enc, wire, jsonv2.Deterministic(true))
}
func isValidASCIIToken(raw string, maxLen int) bool {
	return len(raw) > 0 && len(raw) <= maxLen && !strings.ContainsFunc(raw, func(r rune) bool { return r < 0x21 || r > 0x7E })
}
func hasForbiddenControl(s string) bool {
	return !utf8.ValidString(s) || strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
	})
}
func isValidRFC3339Time(t time.Time) bool {
	return !t.IsZero() && t.UTC().Year() >= 1 && t.UTC().Year() <= 9999
}

// sanitizeBoundedText 校验并规范化单行非敏感说明文本，拒绝非法 UTF-8、控制字符、Bidi/Cf 字符与超长输入。
func sanitizeBoundedText(raw string, maxBytes int, allowEmpty bool, baseErr error) (string, error) {
	if trimmed := strings.TrimSpace(raw); trimmed == "" {
		return "", pickIf[error](allowEmpty, nil, domi18n.EF(baseErr, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "text")))
	} else if len(trimmed) > maxBytes || hasForbiddenControl(trimmed) {
		return "", domi18n.EF(baseErr, domi18n.KeyCommonInvalidTextChars, domi18n.Str("field", "text"))
	} else {
		return trimmed, nil
	}
}
