package credentialhelper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
)

const (
	// DefaultPassPrefix 是 pass 存储项在 password-store 中的默认根路径前缀。
	DefaultPassPrefix = "xops"

	// DefaultPassCommand 是原生 pass 命令行工具的二进制名称。
	DefaultPassCommand = "pass"
)

// PassStoreConfig 描述 pass 凭据存储配置。
type PassStoreConfig struct {
	Prefix           string
	Command          string
	Args             []string
	Env              []string
	Timeout          time.Duration
	ReadOnly         bool
	IsHelperProtocol bool
}

// PassStore 提供基于 pass 密码管理器的凭据存储实现。
// 支持原生 pass 命令行工具或遵循 Helper 协议 v1 的 pass helper 二进制。
type PassStore struct {
	storeID  string
	prefix   string
	command  string
	args     []string
	env      []string
	timeout  time.Duration
	readOnly bool
	helper   *HelperStore
}

// NewPassStore 创建 pass 凭据存储实例。
func NewPassStore(storeID string, cfg PassStoreConfig) (*PassStore, error) {
	if strings.TrimSpace(storeID) == "" {
		return nil, fmt.Errorf("storeID cannot be empty")
	}

	cmdName := strings.TrimSpace(cfg.Command)
	if cmdName == "" {
		cmdName = DefaultPassCommand
	}

	prefix := strings.Trim(strings.TrimSpace(cfg.Prefix), "/")
	if prefix == "" {
		prefix = DefaultPassPrefix
	}

	ps := &PassStore{
		storeID:  storeID,
		prefix:   prefix,
		command:  cmdName,
		args:     cfg.Args,
		env:      cfg.Env,
		timeout:  cfg.Timeout,
		readOnly: cfg.ReadOnly,
	}

	// 若显式声明为 Helper 协议，或者指定的命令为明确的 helper 二进制，组装为 HelperStore 代理
	baseCmd := filepath.Base(cmdName)
	if cfg.IsHelperProtocol || strings.HasPrefix(baseCmd, "xops-credential-") || baseCmd == "pass-helper" {
		opts := ProcessOptions{
			Command: cmdName,
			Args:    cfg.Args,
			Env:     cfg.Env,
			Timeout: cfg.Timeout,
		}
		hs, err := NewHelperStore(storeID, opts, cfg.ReadOnly)
		if err != nil {
			return nil, fmt.Errorf("initialize pass helper store: %w", err)
		}
		ps.helper = hs
	}

	return ps, nil
}

// StoreID 返回该存储的注册标识。
func (p *PassStore) StoreID() string {
	return p.storeID
}

// IsReadOnly 返回该存储是否为只读。
func (p *PassStore) IsReadOnly() bool {
	return p.readOnly
}

func (p *PassStore) resolveItemPath(ref credential.Ref) string {
	if p.prefix != "" {
		return fmt.Sprintf("%s/%s/%s", p.prefix, ref.StoreID, ref.ItemID)
	}
	return fmt.Sprintf("%s/%s", ref.StoreID, ref.ItemID)
}

// Get 从 pass 中检索凭据。
func (p *PassStore) Get(ctx context.Context, ref credential.Ref) (credential.Secret, error) {
	if p == nil {
		return credential.Secret{}, fmt.Errorf("pass store is nil")
	}
	if ref.StoreID != p.storeID {
		return credential.Secret{}, fmt.Errorf("%w: store ID mismatch (store %q vs ref %q)", credential.ErrInvalidRef, p.storeID, ref.StoreID)
	}

	if p.helper != nil {
		return p.helper.Get(ctx, ref)
	}

	itemPath := p.resolveItemPath(ref)
	args := make([]string, 0, len(p.args)+2)
	args = append(args, p.args...)
	args = append(args, "show", itemPath)

	stdout, stderr, err := p.executePassCmd(ctx, args, nil)
	if err != nil {
		stderrLower := strings.ToLower(stderr)
		if strings.Contains(stderrLower, "is not in the password store") || strings.Contains(stderrLower, "not found") {
			return credential.Secret{}, credential.ErrCredentialNotFound
		}
		if strings.Contains(stderrLower, "decryption failed") || strings.Contains(stderrLower, "pinentry") {
			return credential.Secret{}, credential.ErrCredentialStoreLocked
		}
		if strings.Contains(stderrLower, "no secret key") || strings.Contains(stderrLower, "gpg") {
			return credential.Secret{}, credential.ErrCredentialStoreUnavailable
		}
		return credential.Secret{}, fmt.Errorf("pass show failed: %w", err)
	}

	// 截取第一行或非空内容
	content := bytes.TrimRight(stdout, "\r\n")
	if len(content) == 0 {
		return credential.Secret{}, credential.ErrCredentialNotFound
	}

	sec := credential.NewSecret(content)
	// 清零临时读出的字节数组
	for i := range content {
		content[i] = 0
	}
	return sec, nil
}

// Put 向 pass 中插入或更新凭据。机密通过 stdin 传递，严禁进入 argv。
func (p *PassStore) Put(ctx context.Context, ref credential.Ref, secret credential.Secret) error {
	if p == nil {
		return fmt.Errorf("pass store is nil")
	}
	if p.readOnly {
		return credential.ErrCredentialStoreReadOnly
	}
	if ref.StoreID != p.storeID {
		return fmt.Errorf("%w: store ID mismatch (store %q vs ref %q)", credential.ErrInvalidRef, p.storeID, ref.StoreID)
	}

	if p.helper != nil {
		return p.helper.Put(ctx, ref, secret)
	}

	itemPath := p.resolveItemPath(ref)
	args := make([]string, 0, len(p.args)+4)
	args = append(args, p.args...)
	args = append(args, "insert", "-m", "-f", itemPath)

	_, _, err := p.executePassCmd(ctx, args, secret.Value)
	if err != nil {
		return fmt.Errorf("pass insert failed: %w", err)
	}
	return nil
}

// Delete 从 pass 中删除指定凭据项。
func (p *PassStore) Delete(ctx context.Context, ref credential.Ref) error {
	if p == nil {
		return fmt.Errorf("pass store is nil")
	}
	if p.readOnly {
		return credential.ErrCredentialStoreReadOnly
	}
	if ref.StoreID != p.storeID {
		return fmt.Errorf("%w: store ID mismatch (store %q vs ref %q)", credential.ErrInvalidRef, p.storeID, ref.StoreID)
	}

	if p.helper != nil {
		return p.helper.Delete(ctx, ref)
	}

	itemPath := p.resolveItemPath(ref)
	args := make([]string, 0, len(p.args)+3)
	args = append(args, p.args...)
	args = append(args, "rm", "-f", itemPath)

	_, _, err := p.executePassCmd(ctx, args, nil)
	if err != nil {
		return fmt.Errorf("pass rm failed: %w", err)
	}
	return nil
}

func (p *PassStore) executePassCmd(ctx context.Context, args []string, stdinData []byte) ([]byte, string, error) {
	execCtx := ctx
	var cancel context.CancelFunc
	if p.timeout > 0 {
		execCtx, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(execCtx, p.command, args...)
	if len(p.env) > 0 {
		cmd.Env = append(os.Environ(), p.env...)
	}
	configureProcessIsolation(cmd)

	if len(stdinData) > 0 {
		cmd.Stdin = bytes.NewReader(stdinData)
	}

	stdoutLimiter := &limitedBuffer{limit: MaxResponseBytes}
	stderrLimiter := &limitedBuffer{limit: MaxStderrBytes}
	cmd.Stdout = stdoutLimiter
	cmd.Stderr = stderrLimiter

	err := cmd.Run()
	if execCtx.Err() != nil {
		if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
			return nil, "", fmt.Errorf("%w: pass command timed out after %v", credential.ErrCredentialStoreUnavailable, p.timeout)
		}
		return nil, "", fmt.Errorf("pass command canceled: %w", execCtx.Err())
	}

	stderrStr := formatStderr(stderrLimiter.buf.String())
	if err != nil {
		if stderrStr != "" {
			return nil, stderrStr, fmt.Errorf("%w: %s", err, stderrStr)
		}
		return nil, "", err
	}

	return stdoutLimiter.buf.Bytes(), stderrStr, nil
}
