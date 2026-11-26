// Package keychain 实现基于 macOS Security.framework（经纯 Go purego.SyscallN，CGO_ENABLED=0）
// 的本机钥匙串凭据存储适配器（ADR-011 / P4-T4）。
//
// 本子包在物理上与 vault/offline 隔离，所有动态库句柄与符号地址均存于适配器结构体字段
// （0 init()、0 包级 var、0 //nolint:），并强制关闭系统交互弹窗以避免无头环境阻塞。
package keychain

import (
	"context"
	"fmt"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
)

const servicePrefix = "xops:"

// Backend 定义可注入的底层 macOS Keychain 读写后端（供跨平台契约测试与真实 darwin 实现共享）。
type Backend interface {
	Read(service, account string) ([]byte, error)
	Write(service, account string, box *secret.SecretBox) error
	Delete(service, account string) error
}

// Store 实现 ports.SecretVault，通过 macOS Keychain 安全存取凭据；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type Store struct {
	backend Backend
	valid   bool
}

// NewStore 构造使用当前平台原生 macOS Keychain 后端的 Store（非 darwin 返回 ErrUnsupported 后端）。
func NewStore() *Store {
	return &Store{backend: newPlatformBackend(), valid: true}
}

// NewStoreWithBackend 使用显式注入后端构造 Store（供跨平台 TCK 与确定性测试复用）。
func NewStoreWithBackend(backend Backend) (*Store, error) {
	if backend == nil {
		return nil, fmt.Errorf("%w: keychain Backend 不能为 nil", ports.ErrInvalidArgument)
	}
	return &Store{backend: backend, valid: true}, nil
}

// ServiceAccount 为凭据引用构造规范 macOS Keychain (service, account) 键对。
func ServiceAccount(ref secret.Ref) (service, account string) {
	if !ref.IsValid() {
		return "", ""
	}
	return servicePrefix + ref.Store(), ref.Item()
}

// WithSecret 读取钥匙串条目并在同步闭包内借出 *secret.SecretBox，退出前无条件清零底层明文。
//
//xops:syncclosure
//xops:borrowed
func (s *Store) WithSecret(ctx context.Context, ref secret.Ref, fn func(box *secret.SecretBox) error) error {
	if err := s.checkArgs(ctx, ref); err != nil {
		return err
	}
	if fn == nil {
		return ports.ErrNilCallback
	}
	svc, acct := ServiceAccount(ref)
	raw, err := s.backend.Read(svc, acct)
	if err != nil {
		return err
	}
	defer clear(raw)
	return secret.WithBytes(raw, func(box *secret.SecretBox) error { return fn(box) })
}

// PutAndVerify 写入钥匙串条目并立即回读执行常量时间 SecretBox.Equal 校验，失配返回 ports.ErrSecretVerifyFailed。
func (s *Store) PutAndVerify(
	ctx context.Context,
	ref secret.Ref,
	//xops:borrowed
	box *secret.SecretBox,
) error {
	if err := s.checkArgs(ctx, ref); err != nil {
		return err
	}
	if !box.IsValid() {
		return fmt.Errorf("%w: SecretBox 无效", ports.ErrInvalidArgument)
	}
	svc, acct := ServiceAccount(ref)
	if err := s.backend.Write(svc, acct, box); err != nil {
		return err
	}
	return s.WithSecret(ctx, ref, func(got *secret.SecretBox) error {
		if !got.Equal(box) {
			return ports.ErrSecretVerifyFailed
		}
		return nil
	})
}

// Delete 删除指定钥匙串条目；条目不存在返回 ports.ErrSecretNotFound。
func (s *Store) Delete(ctx context.Context, ref secret.Ref) error {
	if err := s.checkArgs(ctx, ref); err != nil {
		return err
	}
	svc, acct := ServiceAccount(ref)
	return s.backend.Delete(svc, acct)
}

func (s *Store) checkArgs(ctx context.Context, ref secret.Ref) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || !s.valid || s.backend == nil {
		return fmt.Errorf("%w: keychain Store 未初始化", ports.ErrInvalidArgument)
	}
	if !ref.IsValid() {
		return fmt.Errorf("%w: 无效凭据引用", ports.ErrInvalidArgument)
	}
	return nil
}
