package credentialhelper

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
)

// DefaultSystemHelperCommand 是系统密钥库 helper 的默认二进制名称。
const DefaultSystemHelperCommand = "xops-credential-system"

// SystemStoreConfig 包含系统密钥库后端的配置选项。
type SystemStoreConfig struct {
	Command  string
	Args     []string
	Env      []string
	Timeout  time.Duration
	ReadOnly bool
}

// SystemStore 封装操作系统原生密钥库或外部 helper 的凭据存储。
type SystemStore struct {
	storeID  string
	readOnly bool
	helper   *HelperStore
	native   credential.Store
}

// NewSystemStore 创建系统密钥库存储实例。
func NewSystemStore(storeID string, cfg SystemStoreConfig) (*SystemStore, error) {
	if strings.TrimSpace(storeID) == "" {
		storeID = "system"
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultHelperTimeout
	}
	cfg.Timeout = timeout

	// 若显式配置了外部 command，遵循 Helper 协议代理调用
	if strings.TrimSpace(cfg.Command) != "" {
		opts := ProcessOptions{
			Command: cfg.Command,
			Args:    cfg.Args,
			Env:     cfg.Env,
			Timeout: timeout,
		}
		hs, err := NewHelperStore(storeID, opts, cfg.ReadOnly)
		if err != nil {
			return nil, fmt.Errorf("initialize system helper store: %w", err)
		}
		return &SystemStore{
			storeID:  storeID,
			readOnly: cfg.ReadOnly,
			helper:   hs,
		}, nil
	}

	// 否则启用原生系统密钥库实现
	nativeStore, err := newNativeSystemStore(storeID, cfg)
	if err != nil {
		return nil, fmt.Errorf("initialize native system credential store: %w", err)
	}

	return &SystemStore{
		storeID:  storeID,
		readOnly: cfg.ReadOnly,
		native:   nativeStore,
	}, nil
}

// StoreID 返回该存储的注册标识。
func (s *SystemStore) StoreID() string {
	return s.storeID
}

// IsReadOnly 返回该存储是否为只读。
func (s *SystemStore) IsReadOnly() bool {
	return s.readOnly
}

// Get 从系统密钥库检索凭据。
func (s *SystemStore) Get(ctx context.Context, ref credential.Ref) (credential.Secret, error) {
	if s == nil {
		return credential.Secret{}, fmt.Errorf("system store is nil")
	}
	if ref.StoreID != s.storeID {
		return credential.Secret{}, fmt.Errorf("%w: store ID mismatch (store %q vs ref %q)", credential.ErrInvalidRef, s.storeID, ref.StoreID)
	}
	if s.helper != nil {
		return s.helper.Get(ctx, ref)
	}
	if s.native != nil {
		return s.native.Get(ctx, ref)
	}
	return credential.Secret{}, credential.ErrCredentialStoreUnavailable
}

// Put 向系统密钥库写入凭据。
func (s *SystemStore) Put(ctx context.Context, ref credential.Ref, secret credential.Secret) error {
	if s == nil {
		return fmt.Errorf("system store is nil")
	}
	if s.readOnly {
		return credential.ErrCredentialStoreReadOnly
	}
	if ref.StoreID != s.storeID {
		return fmt.Errorf("%w: store ID mismatch (store %q vs ref %q)", credential.ErrInvalidRef, s.storeID, ref.StoreID)
	}
	if s.helper != nil {
		return s.helper.Put(ctx, ref, secret)
	}
	if s.native != nil {
		return s.native.Put(ctx, ref, secret)
	}
	return credential.ErrCredentialStoreUnavailable
}

// Delete 从系统密钥库删除凭据。
func (s *SystemStore) Delete(ctx context.Context, ref credential.Ref) error {
	if s == nil {
		return fmt.Errorf("system store is nil")
	}
	if s.readOnly {
		return credential.ErrCredentialStoreReadOnly
	}
	if ref.StoreID != s.storeID {
		return fmt.Errorf("%w: store ID mismatch (store %q vs ref %q)", credential.ErrInvalidRef, s.storeID, ref.StoreID)
	}
	if s.helper != nil {
		return s.helper.Delete(ctx, ref)
	}
	if s.native != nil {
		return s.native.Delete(ctx, ref)
	}
	return credential.ErrCredentialStoreUnavailable
}

// CheckSystemAvailability 检查当前平台系统密钥库环境是否满足可用性前置要求。
func CheckSystemAvailability() error {
	return checkPlatformSystemAvailability()
}
