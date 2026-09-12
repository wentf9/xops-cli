package credentialhelper

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/pkg/credential"
)

// HelperStore 基于外部 credential helper 进程实现 credential.Store 接口。
type HelperStore struct {
	storeID  string
	opts     ProcessOptions
	readOnly bool
}

// NewHelperStore 创建外部 credential helper 存储实例。
func NewHelperStore(storeID string, opts ProcessOptions, readOnly bool) (*HelperStore, error) {
	if strings.TrimSpace(storeID) == "" {
		return nil, fmt.Errorf("storeID cannot be empty")
	}
	if strings.TrimSpace(opts.Command) == "" {
		return nil, fmt.Errorf("helper command cannot be empty")
	}
	return &HelperStore{
		storeID:  storeID,
		opts:     opts,
		readOnly: readOnly,
	}, nil
}

// StoreID 返回该存储的注册标识。
func (s *HelperStore) StoreID() string {
	return s.storeID
}

// IsReadOnly 返回该存储是否为只读模式。
func (s *HelperStore) IsReadOnly() bool {
	return s.readOnly
}

// Get 从 helper 中获取凭据。
func (s *HelperStore) Get(ctx context.Context, ref credential.Ref) (credential.Secret, error) {
	if s == nil {
		return credential.Secret{}, fmt.Errorf("helper store is nil")
	}
	if ref.StoreID != s.storeID {
		return credential.Secret{}, fmt.Errorf("%w: store ID mismatch (store %q vs ref %q)", credential.ErrInvalidRef, s.storeID, ref.StoreID)
	}

	req := &Request{
		ProtocolVersion: ProtocolVersion,
		StoreID:         ref.StoreID,
		ItemID:          ref.ItemID,
	}

	resp, err := Run(ctx, s.opts, ActionGet, req)
	if err != nil {
		return credential.Secret{}, err
	}

	raw, err := DecodeSecretBytes(resp)
	if err != nil {
		return credential.Secret{}, err
	}
	if raw == nil {
		return credential.Secret{}, credential.ErrCredentialNotFound
	}
	defer func() {
		// 确保临时解码缓冲区安全清零
		for i := range raw {
			raw[i] = 0
		}
	}()

	if resp.ExpiresAt != nil {
		return credential.NewSecretWithExpiry(raw, *resp.ExpiresAt), nil
	}
	return credential.NewSecret(raw), nil
}

// Put 向 helper 中写入凭据。只读模式下直接拒绝。
func (s *HelperStore) Put(ctx context.Context, ref credential.Ref, secret credential.Secret) error {
	if s == nil {
		return fmt.Errorf("helper store is nil")
	}
	if s.readOnly {
		return credential.ErrCredentialStoreReadOnly
	}
	if ref.StoreID != s.storeID {
		return fmt.Errorf("%w: store ID mismatch (store %q vs ref %q)", credential.ErrInvalidRef, s.storeID, ref.StoreID)
	}

	req := &Request{
		ProtocolVersion: ProtocolVersion,
		StoreID:         ref.StoreID,
		ItemID:          ref.ItemID,
		Secret:          base64.StdEncoding.EncodeToString(secret.Value),
	}

	_, err := Run(ctx, s.opts, ActionStore, req)
	return err
}

// Delete 从 helper 中删除凭据。只读模式下直接拒绝。
func (s *HelperStore) Delete(ctx context.Context, ref credential.Ref) error {
	if s == nil {
		return fmt.Errorf("helper store is nil")
	}
	if s.readOnly {
		return credential.ErrCredentialStoreReadOnly
	}
	if ref.StoreID != s.storeID {
		return fmt.Errorf("%w: store ID mismatch (store %q vs ref %q)", credential.ErrInvalidRef, s.storeID, ref.StoreID)
	}

	req := &Request{
		ProtocolVersion: ProtocolVersion,
		StoreID:         ref.StoreID,
		ItemID:          ref.ItemID,
	}

	_, err := Run(ctx, s.opts, ActionErase, req)
	return err
}
