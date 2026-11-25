// Package ports 定义 XOps v2 六边形核心的全部出站端口契约（公开契约 2，ADR-002 / ADR-003）。
//
// 本包仅允许依赖 core/domain/** 与受控标准库，严禁引入 core/internal/**、core/osfs、core/conc、
// core/events、testing 或具体协议实现库；全作用域闭包（//xops:syncclosure + //xops:borrowed）、
// 双模态本地 FS 隔离（ScopedRootFS vs OperatorReadFS）、失败关闭零值与严格 json/v2 编解码均由本包确立。
package ports

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
)

const (
	maxPortTokenLen    = 128
	maxPortDetailBytes = 512
	maxPortEnvCount    = 256
	maxPortEnvValBytes = 8192
)

// 本包导出的规范化哨兵错误，供用例、连接池、能力门控、宿主适配器、仿真器与 TCK 统一以 errors.Is 判定。
var (
	// 通用契约与参数错误。
	ErrNilContext       = errors.New("ports: context 不能为 nil")
	ErrNilCallback      = errors.New("ports: 作用域回调函数不能为 nil")
	ErrNilReceiver      = errors.New("ports: 反序列化目标接收者不能为 nil")
	ErrInvalidArgument  = errors.New("ports: 端口调用参数无效")
	ErrUnsupported      = errors.New("ports: 当前适配器不支持该操作")
	ErrClosed           = errors.New("ports: 端口或会话已关闭")
	ErrNotFound         = errors.New("ports: 目标资源不存在")
	ErrAlreadyExists    = errors.New("ports: 目标资源已存在")
	ErrPermissionDenied = errors.New("ports: 权限不足或安全策略拒绝")
	ErrLimitExceeded    = errors.New("ports: 数据超出安全大小或数量上限")

	// 配置存储、CAS 与持久化结果错误。
	ErrRevisionConflict  = errors.New("ports: 资产配置版本 CAS 冲突")
	ErrCorruptData       = errors.New("ports: 持久化数据损坏或完整性校验失败")
	ErrInvalidRevision   = errors.New("ports: 无效的配置版本 Revision")
	ErrInvalidDurability = errors.New("ports: 无效的持久化提交结果 DurabilityOutcome")

	// 本地双模态文件系统与文件锁错误。
	ErrInvalidLockMode   = errors.New("ports: 无效的文件锁模式 LockMode")
	ErrInvalidReadLimits = errors.New("ports: 无效的读取上限 ReadLimits")
	ErrLockBusy          = errors.New("ports: 文件锁已被其他持有者占用")
	ErrNotRegularFile    = errors.New("ports: 目标路径不是常规文件")
	ErrSymlinkRejected   = errors.New("ports: 符号链接被当前安全策略拒绝")
	ErrHandleExpired     = errors.New("ports: 作用域借用句柄已超出生命周期并失效")

	// 凭据库、签名器与主机密钥信任错误。
	ErrVaultLocked        = errors.New("ports: 凭据库处于锁定状态")
	ErrSecretNotFound     = errors.New("ports: 凭据条目不存在")
	ErrSecretVerifyFailed = errors.New("ports: 凭据写入后常量时间回读校验不一致")
	ErrHostKeyMismatch    = errors.New("ports: 远端主机密钥指纹与信任库不匹配")
	ErrHostKeyUnknown     = errors.New("ports: 远端主机密钥未知且策略禁止自动信任")
	ErrHostKeyRevoked     = errors.New("ports: 远端主机密钥已被吊销")
	ErrSignerUnavailable  = errors.New("ports: 密钥签名器或 SSH Agent 不可用")

	// 传输拨号、多路复用与远端 SFTP 错误。
	ErrDialFailed           = errors.New("ports: 建立远端传输连接失败")
	ErrAuthFailed           = errors.New("ports: 远端身份认证失败")
	ErrMuxUnavailable       = errors.New("ports: 多路复用控制套接字不可用")
	ErrRemoteAnchorMismatch = errors.New("ports: 远端文件 FSTAT 类型或 (dev,ino) 锚点不匹配")
	ErrRemoteIsDir          = errors.New("ports: 远端目标为目录而非文件")

	// 安全审计、崩溃对账、系统与交互错误。
	ErrAuditWriteFailed         = errors.New("ports: 审计日志写入失败")
	ErrAuditPostWrite           = errors.New("ports: 审计后置终态写入失败")
	ErrAuditHalted              = errors.New("ports: 审计门控已触发 Halted 熔断")
	ErrInvalidAuditEntry        = errors.New("ports: 无效的审计记录 AuditEntry")
	ErrInvalidProcessInstanceID = errors.New("ports: 无效的进程实例标识 ProcessInstanceID")
	ErrInteractionUnavailable   = errors.New("ports: 当前运行环境不支持用户交互")
	ErrInteractionCanceled      = errors.New("ports: 用户取消或拒绝交互请求")
	ErrEntropyShortRead         = errors.New("ports: 熵源读取字节数不足")
	ErrInvalidTTYSize           = errors.New("ports: 无效的终端窗口尺寸 TerminalSize")
)

func pickIf[T any](ok bool, yes, no T) T {
	if ok {
		return yes
	}
	return no
}
func zeroVal[T any]() (z T) { return z }
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
func marshalValidJSON[W any](enc *jsontext.Encoder, valid bool, badErr error, wire W) error {
	if enc == nil {
		return fmt.Errorf("%w: encoder 不能为 nil", ErrInvalidArgument)
	}
	if !valid {
		return badErr
	}
	return jsonv2.MarshalEncode(enc, wire, jsonv2.Deterministic(true))
}
func isValidASCIIToken(raw string, maxLen int) bool {
	if len(raw) == 0 || len(raw) > maxLen {
		return false
	}
	for i := range len(raw) {
		if raw[i] < 0x21 || raw[i] > 0x7E {
			return false
		}
	}
	return true
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
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", pickIf[error](allowEmpty, nil, fmt.Errorf("%w: 文本不能为空", baseErr))
	}
	if len(trimmed) > maxBytes || hasForbiddenControl(trimmed) {
		return "", fmt.Errorf("%w: 文本超长或包含非法 UTF-8/控制/Bidi 字符", baseErr)
	}
	return trimmed, nil
}
