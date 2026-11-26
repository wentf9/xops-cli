package vault

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
)

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
	valid        bool
}

// NewRouterVault 校验注册表并构造不可变 RouterVault（深拷贝注册表防止外部并发篡改）。
func NewRouterVault(spec RouterSpec) (*RouterVault, error) {
	if len(spec.Stores) == 0 && spec.DefaultStore == nil {
		return nil, fmt.Errorf("%w: RouterVault 至少需要配置一个存储后端或 DefaultStore", ports.ErrInvalidArgument)
	}
	copied := make(map[string]ports.SecretVault, len(spec.Stores))
	for k, v := range spec.Stores {
		if k == "" || v == nil {
			return nil, fmt.Errorf("%w: 凭据存储名 %q 或后端实现无效", ports.ErrInvalidArgument, k)
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

func (r *RouterVault) resolve(ctx context.Context, ref secret.Ref) (ports.SecretVault, error) {
	if ctx == nil {
		return nil, ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil || !r.valid {
		return nil, fmt.Errorf("%w: RouterVault 未初始化", ports.ErrInvalidArgument)
	}
	if !ref.IsValid() {
		return nil, fmt.Errorf("%w: 无效凭据引用", ports.ErrInvalidArgument)
	}
	if b, ok := r.stores[ref.Store()]; ok {
		return b, nil
	}
	if r.defaultStore != nil {
		return r.defaultStore, nil
	}
	return nil, fmt.Errorf("%w: 未注册凭据存储 %q", ports.ErrSecretNotFound, ref.Store())
}
