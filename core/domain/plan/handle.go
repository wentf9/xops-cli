package plan

import (
	"cmp"
	"encoding/hex"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/security"
)

const (
	handleIDEntropyBytes   = 16
	managedHandleDomainTag = "xops.plan.managed_handle.v1"
)

// HandleKind 是长生命周期 SlotMap 世代句柄的编译期封闭幻影类型约束（ADR-009），
// 借助泛型参数 K 物理隔离 PTY、Tunnel、Transfer、Mux 与 Session 句柄，杜绝跨类别误用。
//
//xops:failclosed
type HandleKind interface {
	sealedHandleKind()
}

type sealedHandleMixin struct{}

func (sealedHandleMixin) sealedHandleKind() {}

type (
	// KindPTY 表示持久交互终端会话句柄类别。
	KindPTY struct{ sealedHandleMixin }
	// KindTunnel 表示端口转发 / StreamLocal / TUN 隧道句柄类别。
	KindTunnel struct{ sealedHandleMixin }
	// KindTransfer 表示可恢复文件传输 / SFTP 工作区句柄类别。
	KindTransfer struct{ sealedHandleMixin }
	// KindMux 表示 ControlMaster / ControlPersist 多路复用守护句柄类别。
	KindMux struct{ sealedHandleMixin }
	// KindSession 表示通用托管连接会话句柄类别。
	KindSession struct{ sealedHandleMixin }
)

// HandleKindCode 是幻影类型集 HandleKind 对应的可序列化枚举；零值 HandleKindInvalid 失败关闭。
//
//xops:opaque
//xops:failclosed
type HandleKindCode uint8

const (
	HandleKindInvalid  HandleKindCode = iota // 无效句柄类别（零值失败关闭）
	HandleKindPTY                            // 对应 KindPTY
	HandleKindTunnel                         // 对应 KindTunnel
	HandleKindTransfer                       // 对应 KindTransfer
	HandleKindMux                            // 对应 KindMux
	HandleKindSession                        // 对应 KindSession
)

// HandleKindOf 在编译期类型参数 K 与运行期 HandleKindCode 间建立穷尽映射；接口零值返回 HandleKindInvalid。
func HandleKindOf[K HandleKind]() HandleKindCode {
	var zero K
	return handleKindFromValue(zero)
}

func handleKindFromValue(k HandleKind) HandleKindCode {
	switch k.(type) {
	case KindPTY, *KindPTY:
		return HandleKindPTY
	case KindTunnel, *KindTunnel:
		return HandleKindTunnel
	case KindTransfer, *KindTransfer:
		return HandleKindTransfer
	case KindMux, *KindMux:
		return HandleKindMux
	case KindSession, *KindSession:
		return HandleKindSession
	default:
		return HandleKindInvalid
	}
}

// ParseHandleKindCode 严格解析规范小写句柄类别（pty/tunnel/transfer/mux/session）。
func ParseHandleKindCode(raw string) (HandleKindCode, error) {
	if raw != "" && !strings.ContainsFunc(raw, isForbiddenRune) {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "pty":
			return HandleKindPTY, nil
		case "tunnel":
			return HandleKindTunnel, nil
		case "transfer":
			return HandleKindTransfer, nil
		case "mux":
			return HandleKindMux, nil
		case "session":
			return HandleKindSession, nil
		}
	}
	return HandleKindInvalid, fmt.Errorf("%w: %q", ErrInvalidHandleKind, raw)
}

func (c HandleKindCode) IsValid() bool { return c >= HandleKindPTY && c <= HandleKindSession }
func (c HandleKindCode) IsZero() bool  { return c == HandleKindInvalid }
func (c HandleKindCode) String() string {
	return enumName(uint8(c), "invalid", "invalid", "pty", "tunnel", "transfer", "mux", "session")
}
func (c HandleKindCode) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, c.IsValid(), c.String(), ErrInvalidHandleKind)
}
func (c HandleKindCode) MarshalText() ([]byte, error) { return c.AppendText(nil) }
func (c *HandleKindCode) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(c, HandleKindInvalid, text, ParseHandleKindCode)
}

// HandleID 表示跨请求托管资源的不可变唯一槽位标识符；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type HandleID struct{ value string }

// HandleIDFromBytes 将 16 字节原始熵确定性编码为 32 位小写十六进制 HandleID。
func HandleIDFromBytes(raw [handleIDEntropyBytes]byte) HandleID {
	return HandleID{value: hex.EncodeToString(raw[:])}
}

// NewHandleIDFrom 从显式注入的熵源 io.Reader 读取 16 字节构造 HandleID（零隐式 crypto/rand）。
func NewHandleIDFrom(entropy io.Reader) (HandleID, error) {
	if entropy == nil {
		return HandleID{}, fmt.Errorf("%w: %w", ErrInvalidHandleID, ErrNilEntropy)
	}
	var buf [handleIDEntropyBytes]byte
	if _, err := io.ReadFull(entropy, buf[:]); err != nil {
		return HandleID{}, fmt.Errorf("%w: %w", ErrInvalidHandleID, err)
	}
	return HandleIDFromBytes(buf), nil
}

// ParseHandleID 校验并构造 HandleID（长度 1..128 的可打印非空白非冒号 ASCII）。
func ParseHandleID(raw string) (HandleID, error) {
	if !isValidASCIIToken(raw, maxHandleIDLen) || strings.ContainsRune(raw, ':') {
		return HandleID{}, fmt.Errorf("%w: %q", ErrInvalidHandleID, raw)
	}
	return HandleID{value: raw}, nil
}

func (id HandleID) IsValid() bool         { return id.value != "" }
func (id HandleID) IsZero() bool          { return id.value == "" }
func (id HandleID) String() string        { return id.value }
func (id HandleID) Equal(o HandleID) bool { return id.IsValid() && o.IsValid() && id.value == o.value }
func (id HandleID) Compare(o HandleID) int {
	if !id.IsValid() || !o.IsValid() {
		return compareValidity(id.IsValid(), o.IsValid())
	}
	return cmp.Compare(id.value, o.value)
}
func (id HandleID) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, id.IsValid(), id.value, ErrInvalidHandleID)
}
func (id HandleID) MarshalText() ([]byte, error) { return id.AppendText(nil) }
func (id *HandleID) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(id, HandleID{}, text, ParseHandleID)
}

// ManagedHandle 表示按封闭句柄类别 K 参数化的不可变世代槽位句柄（ADR-009）：
// 内置正向门控 valid bool 与单调非零世代 gen >= 1，强绑定 Merkle PlanDigest 与 security.OperationBinding；
// 零值恒无效并失败关闭，且经 //xops:canonicalhash 校验 WriteCanonical 100% 全字段覆盖。
//
//xops:opaque
//xops:failclosed
//xops:canonicalhash
type ManagedHandle[K HandleKind] struct {
	id         HandleID
	gen        uint64
	planDigest PlanDigest
	binding    security.OperationBinding
	valid      bool
}

// NewManagedHandle 校验句柄类别 K、HandleID、非零世代 gen>=1、PlanDigest 与 OperationBinding 一致性，
// 构造不可变 ManagedHandle[K]。遵循 INV-E4，binding 必须显式携带且严格匹配 planDigest。
func NewManagedHandle[K HandleKind](id HandleID, gen uint64, planDigest PlanDigest, binding security.OperationBinding) (ManagedHandle[K], error) {
	kind := HandleKindOf[K]()
	if !kind.IsValid() {
		return ManagedHandle[K]{}, fmt.Errorf("%w: %w", ErrInvalidManagedHandle, ErrInvalidHandleKind)
	}
	if !id.IsValid() || gen == 0 || !planDigest.IsValid() || !binding.IsValid() {
		return ManagedHandle[K]{}, fmt.Errorf("%w: id/gen(>=1)/plan_digest/binding 均须有效", ErrInvalidManagedHandle)
	}
	bpd, ok := binding.PlanDigest().Get()
	if !ok || !bpd.Equal(planDigest.SecurityDigest()) {
		return ManagedHandle[K]{}, fmt.Errorf("%w: OperationBinding 必须显式绑定一致的 PlanDigest", ErrInvalidManagedHandle)
	}
	return ManagedHandle[K]{
		id: id, gen: gen, planDigest: planDigest, binding: binding, valid: true,
	}, nil
}

func (h ManagedHandle[K]) IsValid() bool {
	bpd, ok := h.binding.PlanDigest().Get()
	return h.valid && HandleKindOf[K]().IsValid() && h.id.IsValid() && h.gen > 0 &&
		h.planDigest.IsValid() && h.binding.IsValid() && ok && bpd.Equal(h.planDigest.SecurityDigest())
}
func (h ManagedHandle[K]) IsZero() bool { return !h.IsValid() }
func (h ManagedHandle[K]) Kind() HandleKindCode {
	return pickIf(h.IsValid(), HandleKindOf[K](), HandleKindInvalid)
}
func (h ManagedHandle[K]) ID() HandleID       { return h.id }
func (h ManagedHandle[K]) Generation() uint64 { return pickIf(h.IsValid(), h.gen, 0) }
func (h ManagedHandle[K]) PlanDigest() PlanDigest {
	return pickIf(h.IsValid(), h.planDigest, PlanDigest{})
}
func (h ManagedHandle[K]) Binding() security.OperationBinding { return h.binding }

// MatchesGeneration 判断句柄是否有效且处于预期世代 gen。
func (h ManagedHandle[K]) MatchesGeneration(gen uint64) bool {
	return h.IsValid() && gen > 0 && h.gen == gen
}

// MatchesPlan 判断句柄是否有效且绑定至预期 PlanDigest。
func (h ManagedHandle[K]) MatchesPlan(pd PlanDigest) bool {
	return h.IsValid() && h.planDigest.Equal(pd)
}

// Equal 严格比对两个同类别 ManagedHandle[K] 是否均有效且全部字段完全一致。
func (h ManagedHandle[K]) Equal(o ManagedHandle[K]) bool {
	return h.IsValid() && o.IsValid() && h.id.Equal(o.id) && h.gen == o.gen &&
		h.planDigest.Equal(o.planDigest) && h.binding.Equal(o.binding)
}

// String 返回紧凑句柄标识文本 "<kind>:<id>:g<gen>:<plan_digest>"；无效零值返回空串。
func (h ManagedHandle[K]) String() string {
	b, err := h.AppendText(nil)
	if err != nil {
		return ""
	}
	return string(b)
}

// AppendText 实现 encoding.TextAppender（值接收者），输出紧凑不可伪造句柄令牌；零值失败关闭。
func (h ManagedHandle[K]) AppendText(b []byte) ([]byte, error) {
	if !h.IsValid() {
		return nil, ErrInvalidManagedHandle
	}
	b = append(b, HandleKindOf[K]().String()...)
	b = append(b, ':')
	b = append(b, h.id.String()...)
	b = append(b, ":g"...)
	b = strconv.AppendUint(b, h.gen, 10)
	b = append(b, ':')
	return h.planDigest.AppendText(b)
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (h ManagedHandle[K]) MarshalText() ([]byte, error) { return h.AppendText(nil) }

// WriteCanonical 以零反射、长度前缀与域分离方式将 ManagedHandle[K] 全字段写入 w（受 digestcover 校验）。
func (h ManagedHandle[K]) WriteCanonical(w io.Writer) error {
	if w == nil {
		return ErrNilWriter
	}
	if !h.valid || !h.IsValid() {
		return ErrInvalidManagedHandle
	}
	enc := &canonicalEncoder{w: w}
	enc.writeString(managedHandleDomainTag)
	enc.writeUint8(uint8(HandleKindOf[K]()))
	enc.writeString(h.id.String())
	enc.writeUint64(h.gen)
	sum, ok := h.planDigest.Bytes()
	if !ok {
		return ErrInvalidManagedHandle
	}
	enc.writeBytes(sum[:])
	if enc.err == nil {
		enc.fail(h.binding.WriteCanonical(w))
	}
	return enc.err
}

type managedHandleWire struct {
	Kind       algebraic.Option[HandleKindCode]            `json:"kind"`
	ID         algebraic.Option[HandleID]                  `json:"id"`
	Gen        algebraic.Option[uint64]                    `json:"gen"`
	PlanDigest algebraic.Option[PlanDigest]                `json:"plan_digest"`
	Binding    algebraic.Option[security.OperationBinding] `json:"binding"`
}

// MarshalJSONTo 实现 ManagedHandle[K] 的 Go 1.27 encoding/json/v2 完整确定性编码；零值失败关闭。
func (h ManagedHandle[K]) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !h.IsValid() {
		return ErrInvalidManagedHandle
	}
	return jsonv2.MarshalEncode(enc, managedHandleWire{
		Kind:       algebraic.Some(HandleKindOf[K]()),
		ID:         algebraic.Some(h.id),
		Gen:        algebraic.Some(h.gen),
		PlanDigest: algebraic.Some(h.planDigest),
		Binding:    algebraic.Some(h.binding),
	})
}

// UnmarshalJSONFrom 实现 ManagedHandle[K] 的失败关闭解码，强制校验 kind == HandleKindOf[K]() 杜绝跨类别混淆。
func (h *ManagedHandle[K]) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(h, dec, ErrInvalidManagedHandle, func(w managedHandleWire) (ManagedHandle[K], error) {
		kind, okK := w.Kind.Get()
		id, okID := w.ID.Get()
		gen, okG := w.Gen.Get()
		pd, okP := w.PlanDigest.Get()
		binding, okB := w.Binding.Get()
		if !okK || !okID || !okG || !okP || !okB {
			return ManagedHandle[K]{}, fmt.Errorf("%w: 缺少必需的句柄字段", ErrInvalidManagedHandle)
		}
		if kind != HandleKindOf[K]() {
			return ManagedHandle[K]{}, fmt.Errorf("%w: 句柄类别不匹配（got=%s want=%s）", ErrInvalidHandleKind, kind, HandleKindOf[K]())
		}
		return NewManagedHandle[K](id, gen, pd, binding)
	})
}
