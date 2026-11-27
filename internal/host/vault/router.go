package vault

import (
	"context"
	"errors"
	"io"
	"maps"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/i18n"
)

type vaultLocker interface {
	Lock(ctx context.Context) error
}

// RouterSpec 是构造多后端按 Store 名称路由的 RouterVault 的显式入参规格。
type RouterSpec struct {
	// Stores 按 secret.Ref.Store() 名称映射对应的 SecretVault 后端。
	Stores map[string]ports.SecretVault
	// DefaultStore 可选默认后端：当 ref.Store() 未显式登记于 Stores 时回退使用；为空则严格失败关闭。
	DefaultStore ports.SecretVault
}

// RouterVault 实现 ports.SecretVault，按 ref.Store() 将凭据请求确定性路由至对应后端；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type RouterVault struct {
	stores       map[string]ports.SecretVault
	defaultStore ports.SecretVault
	closed       atomic.Bool
	closeOnce    sync.Once
	closeErr     error
	valid        bool
}

// NewRouterVault 校验注册表并构造不可变 RouterVault（深拷贝注册表防止外部并发篡改）。
func NewRouterVault(spec RouterSpec) (*RouterVault, error) {
	if len(spec.Stores) == 0 && spec.DefaultStore == nil {
		return nil, i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostVaultRouterEmpty)
	}
	copied := make(map[string]ports.SecretVault, len(spec.Stores))
	for k, v := range spec.Stores {
		if k == "" || v == nil {
			return nil, i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostVaultRouterInvalidStore, i18n.BoundStr("name", k))
		}
		copied[k] = v
	}
	return &RouterVault{
		stores:       copied,
		defaultStore: spec.DefaultStore,
		valid:        true,
	}, nil
}

// KnownStores 返回当前路由器显式登记的全部存储名称（按字典序排序）。
func (r *RouterVault) KnownStores() []string {
	if r == nil || !r.valid || len(r.stores) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(r.stores))
}

// WithSecret 按 ref.Store() 路由至目标后端并在同步闭包内借出 *secret.SecretBox。
//
//xops:syncclosure
//xops:borrowed
func (r *RouterVault) WithSecret(ctx context.Context, ref secret.Ref, fn func(box *secret.SecretBox) error) error {
	if fn == nil {
		if ctx == nil {
			return ports.ErrNilContext
		}
		return ports.ErrNilCallback
	}
	backend, err := r.resolve(ctx, ref)
	if err != nil {
		return err
	}
	return backend.WithSecret(ctx, ref, func(box *secret.SecretBox) error { return fn(box) })
}

// PutAndVerify 按 ref.Store() 路由至目标后端写入并执行常量时间回读校验。
func (r *RouterVault) PutAndVerify(
	ctx context.Context,
	ref secret.Ref,
	//xops:borrowed
	box *secret.SecretBox,
) error {
	backend, err := r.resolve(ctx, ref)
	if err != nil {
		return err
	}
	return backend.PutAndVerify(ctx, ref, box)
}

// Delete 按 ref.Store() 路由至目标后端删除指定凭据条目。
func (r *RouterVault) Delete(ctx context.Context, ref secret.Ref) error {
	backend, err := r.resolve(ctx, ref)
	if err != nil {
		return err
	}
	return backend.Delete(ctx, ref)
}

// Close 幂等关闭路由器并按确定性顺序对去重后的全部底层后端执行 Lock（清零主密钥）与 Close 释放；
// 关闭后路由器拒绝一切新凭据请求（返回 ports.ErrClosed），供 cmd/xops 逆序停机使用。
func (r *RouterVault) Close() error {
	if r == nil || !r.valid {
		return nil
	}
	r.closeOnce.Do(func() {
		r.closed.Store(true)
		seen := make(map[ports.SecretVault]struct{}, len(r.stores)+1)
		var errs []error
		for _, name := range slices.Sorted(maps.Keys(r.stores)) {
			errs = appendCloseBackend(errs, seen, r.stores[name])
		}
		if r.defaultStore != nil {
			errs = appendCloseBackend(errs, seen, r.defaultStore)
		}
		r.closeErr = errors.Join(errs...)
	})
	return r.closeErr
}

func appendCloseBackend(errs []error, seen map[ports.SecretVault]struct{}, b ports.SecretVault) []error {
	if b == nil {
		return errs
	}
	if _, dup := seen[b]; dup {
		return errs
	}
	seen[b] = struct{}{}
	if l, ok := b.(vaultLocker); ok {
		if err := l.Lock(context.Background()); err != nil && !errors.Is(err, ports.ErrNotFound) && !errors.Is(err, ports.ErrVaultLocked) {
			errs = append(errs, err)
		}
	}
	if c, ok := b.(io.Closer); ok {
		if err := c.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func (r *RouterVault) resolve(ctx context.Context, ref secret.Ref) (ports.SecretVault, error) {
	if ctx == nil {
		return nil, ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil || !r.valid {
		return nil, i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostNotInitialized, i18n.Str("component", "RouterVault"))
	}
	if r.closed.Load() {
		return nil, ports.ErrClosed
	}
	if !ref.IsValid() {
		return nil, i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostInvalidSecretRef)
	}
	if b, ok := r.stores[ref.Store()]; ok {
		return b, nil
	}
	if r.defaultStore != nil {
		return r.defaultStore, nil
	}
	return nil, i18n.EF(ports.ErrSecretNotFound, i18n.KeyHostVaultStoreNotRegistered, i18n.BoundStr("name", ref.Store()))
}
