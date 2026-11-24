package security

import "cmp"

// Capability 是 XOps v2 编译期幻影能力封闭类型集（RFC §3.1），仅用于 core/internal/gate.Authorized[C]
// 等泛型能力证明的类型约束，100% 纯数学且零同步原语。
//
//xops:failclosed
type Capability interface {
	sealedCapability()
}

type sealedCap struct{}

func (sealedCap) sealedCapability() {}

type (
	// CapInspect 表示只读探测、节点/会话列举或状态查询能力。
	CapInspect struct{ sealedCap }
	// CapExecute 表示远端命令执行或交互式 Shell/PTY 会话能力。
	CapExecute struct{ sealedCap }
	// CapFileRead 表示远端文件读取或元信息查询能力。
	CapFileRead struct{ sealedCap }
	// CapFileMut 表示远端文件写入、补丁修改或目录结构变更能力。
	CapFileMut struct{ sealedCap }
	// CapTransfer 表示跨主机文件传输（SCP、SFTP、MCP HTTP 分片流）能力。
	CapTransfer struct{ sealedCap }
	// CapTunnel 表示 SSH 端口转发（-L/-R/-D/StreamLocal/TUN）能力。
	CapTunnel struct{ sealedCap }
	// CapMutate 表示本机配置、凭据 Vault 或已知主机信任库变更能力。
	CapMutate struct{ sealedCap }
)

// Kind 返回 CapInspect 对应的运行期能力类别。
func (CapInspect) Kind() CapabilityKind { return CapabilityInspect }

// Kind 返回 CapExecute 对应的运行期能力类别。
func (CapExecute) Kind() CapabilityKind { return CapabilityExecute }

// Kind 返回 CapFileRead 对应的运行期能力类别。
func (CapFileRead) Kind() CapabilityKind { return CapabilityFileRead }

// Kind 返回 CapFileMut 对应的运行期能力类别。
func (CapFileMut) Kind() CapabilityKind { return CapabilityFileMut }

// Kind 返回 CapTransfer 对应的运行期能力类别。
func (CapTransfer) Kind() CapabilityKind { return CapabilityTransfer }

// Kind 返回 CapTunnel 对应的运行期能力类别。
func (CapTunnel) Kind() CapabilityKind { return CapabilityTunnel }

// Kind 返回 CapMutate 对应的运行期能力类别。
func (CapMutate) Kind() CapabilityKind { return CapabilityMutate }

// CapabilityKind 是幻影类型集 Capability 对应的可序列化能力枚举；零值恒为 CapabilityInvalid。
//
//xops:opaque
//xops:failclosed
type CapabilityKind uint8

const (
	CapabilityInvalid  CapabilityKind = iota // 零值无效能力（失败关闭默认值）
	CapabilityInspect                        // 对应幻影类型 CapInspect
	CapabilityExecute                        // 对应幻影类型 CapExecute
	CapabilityFileRead                       // 对应幻影类型 CapFileRead
	CapabilityFileMut                        // 对应幻影类型 CapFileMut
	CapabilityTransfer                       // 对应幻影类型 CapTransfer
	CapabilityTunnel                         // 对应幻影类型 CapTunnel
	CapabilityMutate                         // 对应幻影类型 CapMutate
)

// CapabilityKindOf 在编译期类型参数 C 与运行期 CapabilityKind 间建立穷尽映射；接口零值 nil 返回 CapabilityInvalid。
func CapabilityKindOf[C Capability]() CapabilityKind {
	var zero C
	return capabilityKindFromValue(zero)
}

func capabilityKindFromValue(c Capability) CapabilityKind {
	switch c.(type) {
	case CapInspect, *CapInspect:
		return CapabilityInspect
	case CapExecute, *CapExecute:
		return CapabilityExecute
	case CapFileRead, *CapFileRead:
		return CapabilityFileRead
	case CapFileMut, *CapFileMut:
		return CapabilityFileMut
	case CapTransfer, *CapTransfer:
		return CapabilityTransfer
	case CapTunnel, *CapTunnel:
		return CapabilityTunnel
	case CapMutate, *CapMutate:
		return CapabilityMutate
	default:
		return CapabilityInvalid
	}
}

// ParseCapabilityKind 严格解析规范小写能力类别文本。
func ParseCapabilityKind(raw string) (CapabilityKind, error) {
	return parseEnumByName(raw, CapabilityInspect, CapabilityMutate, CapabilityInvalid, CapabilityKind.String, ErrInvalidCapability)
}

// IsValid 报告 k 是否为 7 种合法能力类别之一。
func (k CapabilityKind) IsValid() bool { return k >= CapabilityInspect && k <= CapabilityMutate }

// IsZero 报告 k 是否处于零值无效态。
func (k CapabilityKind) IsZero() bool { return k == CapabilityInvalid }

// Compare 定义 CapabilityKind 上的确定性全序（无效值排在最前）。
func (k CapabilityKind) Compare(other CapabilityKind) int {
	return cmp.Compare(pickIf(k.IsValid(), uint8(k), 0), pickIf(other.IsValid(), uint8(other), 0))
}

// String 返回能力类别的规范小写文本；无效值返回 "invalid"。
func (k CapabilityKind) String() string {
	return enumName(uint8(k), "invalid", "invalid", "inspect", "execute", "file_read", "file_mut", "transfer", "tunnel", "mutate")
}

// AppendText 实现 encoding.TextAppender（值接收者）；对无效值严格失败关闭。
func (k CapabilityKind) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, k.IsValid(), k.String(), ErrInvalidCapability, uint8(k))
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (k CapabilityKind) MarshalText() ([]byte, error) { return k.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；失败时重置为 CapabilityInvalid 并失败关闭。
func (k *CapabilityKind) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(k, CapabilityInvalid, text, ParseCapabilityKind)
}
