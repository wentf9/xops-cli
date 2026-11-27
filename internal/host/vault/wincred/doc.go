// Package wincred 实现基于 Windows Credential Manager（Advapi32 CredReadW/CredWriteW/CredDeleteW）
// 的本机凭据存储适配器（ADR-011 / P4-T4）。
//
// 本子包在物理上与 vault/offline 隔离，使 CredReadW 所需的 unsafe.Slice 不会触发
// vault/offline 的 hasUnsafeVaultForge 防线；所有 DLL/Proc 句柄均存于适配器结构体字段（0 init()、0 pkg var）。
package wincred

import (
	"context"
	"errors"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/i18n"
)

const targetPrefix = "xops:"

// Backend 定义可注入的底层 Windows 凭据读写后端（供跨平台单元测试与真实 Advapi32 实现共享）。
type Backend interface {
	Read(target string) ([]byte, error)
	Write(target, user string, box *secret.SecretBox) error
	Delete(target string) error
}

// Store 实现 ports.SecretVault，通过 Windows Credential Manager 安全存取凭据；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type Store struct {
	backend Backend
	valid   bool
}

// NewStore 构造使用当前平台原生 Windows Credential Manager 后端的 Store（非 Windows 返回 ErrUnsupported 后端）。
func NewStore() *Store {
	return &Store{backend: newPlatformBackend(), valid: true}
}

// NewStoreWithBackend 使用显式注入后端构造 Store（供跨平台 TCK 与确定性故障测试复用）。
func NewStoreWithBackend(backend Backend) (*Store, error) {
	if backend == nil {
		return nil, i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostNilDependency, i18n.Str("field", "wincred.Backend"))
	}
	return &Store{backend: backend, valid: true}, nil
}

// TargetName 为凭据引用构造规范 Windows Credential Manager 目标名（"xops:<store>:<item>"）。
func TargetName(ref secret.Ref) string {
	if !ref.IsValid() {
		return ""
	}
	return targetPrefix + ref.Store() + ":" + ref.Item()
}

// WithSecret 读取凭据并在同步闭包内借出 *secret.SecretBox，退出前无条件清零底层明文缓冲。
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
	raw, err := s.backend.Read(TargetName(ref))
	if err != nil {
		return err
	}
	defer clear(raw)
	return secret.WithBytes(raw, func(box *secret.SecretBox) error { return fn(box) })
}

// PutAndVerify 写入凭据并立即回读执行常量时间 SecretBox.Equal 校验，失配返回 ports.ErrSecretVerifyFailed。
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
		return i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostInvalidSecretBox)
	}
	target := TargetName(ref)
	if err := s.backend.Write(target, ref.Item(), box); err != nil {
		return err
	}
	verifyErr := s.WithSecret(ctx, ref, func(got *secret.SecretBox) error {
		if !got.Equal(box) {
			return ports.ErrSecretVerifyFailed
		}
		return nil
	})
	if verifyErr != nil && !errors.Is(verifyErr, ports.ErrSecretVerifyFailed) && ctx.Err() == nil {
		return domi18n.WrapSentinel(ports.ErrSecretVerifyFailed, verifyErr)
	}
	return verifyErr
}

// Delete 删除目标凭据；目标不存在时返回 ports.ErrSecretNotFound。
func (s *Store) Delete(ctx context.Context, ref secret.Ref) error {
	if err := s.checkArgs(ctx, ref); err != nil {
		return err
	}
	return s.backend.Delete(TargetName(ref))
}

func (s *Store) checkArgs(ctx context.Context, ref secret.Ref) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || !s.valid || s.backend == nil {
		return i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostNotInitialized, i18n.Str("component", "wincred.Store"))
	}
	if !ref.IsValid() {
		return i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostInvalidSecretRef)
	}
	return nil
}
