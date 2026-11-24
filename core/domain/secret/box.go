package secret

import "crypto/subtle"

const redactedSecretPlaceholder = "[REDACTED]"

// SecretBox 是单协程作用域借用机密字节容器（100% 零 sync/atomic）。
//
// 核心不变量：
//   - 全字段私有且禁止包外直接构造（//xops:opaque）；
//   - 同时维护正向有效门控 valid 与销毁标记 wiped，零值、nil 及销毁后均严格失败关闭（//xops:failclosed）；
//   - 故意不实现任何 Text/JSON/Binary 序列化接口且不含任何 json 标签，确保 Go 1.27 encoding/json/v2
//     在尝试编码或解码本类型时原生返回 *json/v2.SemanticError；
//   - 工程安全边界遵循 ADR-016：阻断日志/审计/错误/事件/YAML/计划/摘要泄露，并对自有缓冲执行 clear() 零化。
//
//xops:opaque
//xops:failclosed
type SecretBox struct {
	raw   []byte
	valid bool
	wiped bool
}

// WithBytes 将调用方原始机密字节 raw 深拷贝入受管 SecretBox 并立即 clear(raw)，
// 随后在同步作用域闭包 fn 内借出 *SecretBox；无论 fn 正常返回、返回错误还是发生 panic，
// 退出前均无条件调用 box.Wipe() 清零内部缓冲并永久失效句柄。
//
// runtime/secret.Do 仅精准包裹明文摄入与清零临界区（分配 cp、拷贝与 clear(raw)），
// 不包裹外层调用方回调 fn(box)，避免在 Phase 2–4 场景下将 secret 模式永久遗传给 fn 内派生的
// 长生命周期协程或将非机密堆对象纳入 GC 擦除跟踪；fn 内对明文的真实访问仍经由受 Do 保护的
// box.Use 与 box.Equal 完成。
//
// 安全标注契约（RFC §3.2 / Plan §4.6）：
// 仅标注 //xops:syncclosure 与 //xops:borrowed，严禁标注 //xops:secretuse，
// 以使 core/ports/tck、internal/host/sys 等非明文消费白名单包可合法完成入站构造。
//
//xops:syncclosure
//xops:borrowed
func WithBytes(raw []byte, fn func(box *SecretBox) error) error {
	defer clear(raw)
	if fn == nil {
		return ErrNilCallback
	}
	box := &SecretBox{}
	defer box.Wipe()
	Do(func() {
		cp := make([]byte, len(raw))
		copy(cp, raw)
		clear(raw)
		box.raw = cp
		box.valid = true
	})
	return fn(box)
}

// Use 在同步作用域内以临时防御性副本向 fn 暴露明文字节，回调退出（含 panic）时立即 clear 临时副本。
// 内部使用副本而非暴露底层切片，确保回调对 plain 的原地修改或 clear(plain) 不会破坏同一 SecretBox 的后续读取或比对。
//
// 本方法标注 //xops:secretuse，由 xopsvet/secretbox 静态锁死仅 5 个白名单包可调用，
// 并由 xopsvet/secrettaint 与 linearlease 双重审计回调内明文零逃逸。
//
//xops:syncclosure
//xops:borrowed
//xops:secretuse
func (b *SecretBox) Use(fn func(plain []byte) error) error {
	if b == nil {
		return ErrSecretInvalid
	}
	if b.wiped {
		return ErrSecretWiped
	}
	if !b.valid {
		return ErrSecretInvalid
	}
	if fn == nil {
		return ErrNilCallback
	}
	var cbErr error
	Do(func() {
		buf := make([]byte, len(b.raw))
		copy(buf, b.raw)
		defer clear(buf)
		cbErr = fn(buf)
	})
	return cbErr
}

// Equal 使用 crypto/subtle.ConstantTimeCompare 以常量时间比对两个 SecretBox 的明文内容。
// 本方法免除测试夹具（core/ports/tck）等非白名单包的明文消费需求；
// 严格失败关闭：若任一操作数为 nil、未初始化零值或已销毁（IsValid() == false），恒返回 false。
func (b *SecretBox) Equal(other *SecretBox) bool {
	if !b.IsValid() || !other.IsValid() {
		return false
	}
	equal := false
	Do(func() {
		equal = subtle.ConstantTimeCompare(b.raw, other.raw) == 1
	})
	return equal
}

// Wipe 立即使用 clear() 清零内部字节缓冲并永久失效 SecretBox；可安全重复调用，对 nil 接收者无操作。
func (b *SecretBox) Wipe() {
	if b == nil {
		return
	}
	clear(b.raw)
	b.raw = nil
	b.valid = false
	b.wiped = true
}

// IsValid 报告 SecretBox 当前是否已有效初始化且尚未销毁。
func (b *SecretBox) IsValid() bool {
	if b == nil || !b.valid || b.wiped {
		return false
	}
	return true
}

// IsWiped 报告 SecretBox 是否已经历 Wipe 销毁；对 nil 或未初始化零值返回 false。
func (b *SecretBox) IsWiped() bool {
	if b == nil || !b.wiped {
		return false
	}
	return true
}

// Len 返回有效 SecretBox 持有的字节长度；对 nil、无效零值或已销毁实例返回 0。
func (b *SecretBox) Len() int {
	if !b.IsValid() {
		return 0
	}
	return len(b.raw)
}

// String 返回恒定脱敏占位符，绝不输出明文、哈希或长度（纵深防御，不替代 secretbox 静态拦截）。
// 采用值接收者，确保非可寻址 SecretBox 值与非 nil *SecretBox 指针均满足 fmt.Stringer，
// 避免 fmt 回退到结构体反射打印原始字节（对 (*SecretBox)(nil)，fmt 内置空指针防护会安全输出 <nil>）。
func (b SecretBox) String() string {
	return redactedSecretPlaceholder
}

// GoString 返回恒定脱敏占位符，防止 %#v 格式化意外暴露内部字段。
// 采用值接收者，确保非可寻址 SecretBox 值与非 nil *SecretBox 指针均满足 fmt.GoStringer。
func (b SecretBox) GoString() string {
	return redactedSecretPlaceholder
}
