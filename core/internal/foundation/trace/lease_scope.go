package trace

import (
	"context"
	"fmt"
)

type leaseScopeCtxKey struct{}

// LeaseScope 表示全局单层不可重入连接租约作用域标记。
//
// 本类型仅限连接池在进入用户租约回调（fn(scopedCtx, sess)）入口处注入，严禁 gate、vault、osfs 等其他层级借用；
// 配合 CheckNonReentrant 阻止任何同池或跨池（跨 domain）嵌套二次申请连接租约，从根源消除多池 AB-BA 死锁与通道自锁。
// 其中 domain 仅作为只读诊断归属标签，绝不用于豁免跨池重入。零值代表无效作用域（IsValid() == false）。
//
//xops:opaque
//xops:failclosed
type LeaseScope struct {
	domain  string
	leaseID string
}

// NewLeaseScope 校验并构造全局单层连接租约作用域 LeaseScope。
// domain 仅作为只读诊断归属标签，与 leaseID 均须为长度 1..128 的可打印非空白 ASCII 字符串，否则返回 ErrInvalidLeaseScope。
func NewLeaseScope(domain string, leaseID string) (LeaseScope, error) {
	if !isValidToken(domain) || !isValidToken(leaseID) {
		return LeaseScope{}, ErrInvalidLeaseScope
	}
	return LeaseScope{
		domain:  domain,
		leaseID: leaseID,
	}, nil
}

// IsValid 返回 LeaseScope 是否包含非空的域与租约标识。
func (s LeaseScope) IsValid() bool {
	return s.domain != "" && s.leaseID != ""
}

// Domain 返回只读诊断归属标签（零值返回空串）；该标签仅用于追踪定位，不构成可重入隔离域。
func (s LeaseScope) Domain() string {
	return s.domain
}

// LeaseID 返回租约实例标识（零值返回空串）。
func (s LeaseScope) LeaseID() string {
	return s.leaseID
}

// Equal 比较两个 LeaseScope 是否完全相等。
func (s LeaseScope) Equal(other LeaseScope) bool {
	return s.domain == other.domain && s.leaseID == other.leaseID
}

// WithLeaseScope 将合法的全局单层连接租约作用域标记注入派生上下文（仅限连接池租约回调入口调用）。
// 若 ctx 为 nil（ErrNilContext）、scope 无效（ErrInvalidLeaseScope）或 ctx 已处于任意活跃连接租约作用域内
// （无论 domain 相同与否，均返回 ErrReentrantLease），均采用失败关闭策略直接拒绝并返回错误。
func WithLeaseScope(ctx context.Context, scope LeaseScope) (context.Context, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if !scope.IsValid() {
		return nil, ErrInvalidLeaseScope
	}
	if err := CheckNonReentrant(ctx); err != nil {
		return nil, err
	}
	return context.WithValue(ctx, leaseScopeCtxKey{}, scope), nil
}

// LeaseScopeFromContext 从上下文只读提取当前活跃的 LeaseScope。
// 若 ctx 为 nil 或未处于活跃租约作用域内，则返回零值与 false。
func LeaseScopeFromContext(ctx context.Context) (LeaseScope, bool) {
	if ctx == nil {
		return LeaseScope{}, false
	}
	scope, ok := ctx.Value(leaseScopeCtxKey{}).(LeaseScope)
	if !ok || !scope.IsValid() {
		return LeaseScope{}, false
	}
	return scope, true
}

// InLeaseScope 报告 ctx 当前是否已处于全局单层活跃连接租约作用域中。
func InLeaseScope(ctx context.Context) bool {
	_, ok := LeaseScopeFromContext(ctx)
	return ok
}

// CheckNonReentrant 校验当前上下文未处于任何活跃连接租约作用域内（全局单层防重入，不按 domain 豁免）。
// 若 ctx 为 nil，失败关闭返回 ErrNilContext；若检测到活跃作用域，则返回包装了 ErrReentrantLease 并附带诊断归属信息的错误。
func CheckNonReentrant(ctx context.Context) error {
	if ctx == nil {
		return ErrNilContext
	}
	if scope, ok := LeaseScopeFromContext(ctx); ok {
		return fmt.Errorf("%w: domain=%s lease=%s", ErrReentrantLease, scope.domain, scope.leaseID)
	}
	return nil
}
