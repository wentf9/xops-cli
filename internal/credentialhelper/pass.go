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
	"sync"
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
	NonInteractive   bool
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

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultHelperTimeout
	}

	ps := &PassStore{
		storeID:  storeID,
		prefix:   prefix,
		command:  cmdName,
		args:     cfg.Args,
		env:      cfg.Env,
		timeout:  timeout,
		readOnly: cfg.ReadOnly,
	}

	// 若显式声明为 Helper 协议，或者指定的命令为明确的 helper 二进制，组装为 HelperStore 代理
	baseCmd := filepath.Base(cmdName)
	if cfg.IsHelperProtocol || strings.HasPrefix(baseCmd, "xops-credential-") || baseCmd == "pass-helper" {
		opts := ProcessOptions{
			NonInteractive: cfg.NonInteractive,
			Command:        cmdName,
			Args:           cfg.Args,
			Env:            cfg.Env,
			Timeout:        timeout,
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
		return credential.Secret{}, mapPassError("show", err, stderr)
	}

	// 严禁 TrimRight 去除尾随换行，完整保留原始秘密字节
	if len(stdout) == 0 {
		return credential.Secret{}, credential.ErrCredentialNotFound
	}

	sec := credential.NewSecret(stdout)
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

	_, stderr, err := p.executePassCmd(ctx, args, secret.Value)
	if err != nil {
		return mapPassError("insert", err, stderr)
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

	_, stderr, err := p.executePassCmd(ctx, args, nil)
	if err != nil {
		return mapPassError("rm", err, stderr)
	}
	return nil
}

func (p *PassStore) executePassCmd(ctx context.Context, args []string, stdinData []byte) ([]byte, string, error) {
	timeout := p.timeout
	if timeout <= 0 {
		timeout = DefaultHelperTimeout
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, p.command, args...)
	cmd.Env = passCommandEnv(ctx, p.env)

	waitDelay := DefaultProcessWaitDelay
	if timeout < waitDelay {
		waitDelay = timeout
	}
	cmd.WaitDelay = waitDelay

	if len(stdinData) > 0 {
		cmd.Stdin = bytes.NewReader(stdinData)
	}

	stdoutLimiter := &limitedBuffer{limit: MaxResponseBytes}
	stderrLimiter := &limitedBuffer{limit: MaxStderrBytes}
	cmd.Stdout = stdoutLimiter
	cmd.Stderr = stderrLimiter

	session, err := startProcessSession(execCtx, cmd)
	if err != nil {
		if execCtx.Err() != nil {
			if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
				return nil, "", fmt.Errorf("%w: pass command timed out after %v: %w", credential.ErrCredentialStoreUnavailable, timeout, execCtx.Err())
			}
			return nil, "", fmt.Errorf("pass command canceled: %w", execCtx.Err())
		}
		if isNotFoundErr(err) {
			return nil, "", fmt.Errorf("%w: pass executable not found: %s", credential.ErrCredentialStoreUnavailable, p.command)
		}
		return nil, "", fmt.Errorf("start pass command failed: %w", err)
	}
	defer func() {
		_ = session.Close()
	}()

	cancelDone := make(chan struct{})
	var cancelWg sync.WaitGroup
	cancelWg.Add(1)

	go func() {
		defer cancelWg.Done()
		select {
		case <-execCtx.Done():
			_ = session.KillTree()
		case <-cancelDone:
		}
	}()

	runErr := cmd.Wait()
	close(cancelDone)
	cancelWg.Wait()

	sanitizedStderr := SanitizeDiagnostic(stderrLimiter.buf.String(), string(stdinData))

	if execCtx.Err() != nil {
		_ = session.KillTree()
		if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
			return nil, sanitizedStderr, fmt.Errorf("%w: pass command timed out after %v: %w", credential.ErrCredentialStoreUnavailable, timeout, execCtx.Err())
		}
		return nil, sanitizedStderr, fmt.Errorf("pass command canceled: %w", execCtx.Err())
	}

	// 严格检查 stdout 输出上限
	if stdoutLimiter.total > MaxResponseBytes {
		return nil, sanitizedStderr, fmt.Errorf("%w: pass command output exceeded maximum limit of %d bytes", credential.ErrCredentialStoreUnavailable, MaxResponseBytes)
	}

	if runErr != nil && isNotFoundErr(runErr) {
		return nil, sanitizedStderr, fmt.Errorf("%w: pass executable not found: %s", credential.ErrCredentialStoreUnavailable, p.command)
	}

	if runErr != nil {
		if sanitizedStderr != "" {
			return nil, sanitizedStderr, fmt.Errorf("%w: %s", runErr, sanitizedStderr)
		}
		return nil, sanitizedStderr, runErr
	}

	return stdoutLimiter.buf.Bytes(), sanitizedStderr, nil
}

func mapPassError(action string, err error, stderr string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, credential.ErrCredentialStoreUnavailable) ||
		errors.Is(err, credential.ErrCredentialStoreLocked) ||
		errors.Is(err, credential.ErrCredentialNotFound) ||
		errors.Is(err, credential.ErrCredentialAccessDenied) ||
		errors.Is(err, credential.ErrCredentialStoreReadOnly) {
		return err
	}

	stderrLower := strings.ToLower(stderr)
	errLower := strings.ToLower(err.Error())
	combined := stderrLower + " " + errLower

	if strings.Contains(combined, "is not in the password store") || strings.Contains(combined, "not found") {
		return fmt.Errorf("%w: %w", credential.ErrCredentialNotFound, err)
	}
	if strings.Contains(combined, "decryption failed") || strings.Contains(combined, "pinentry") || strings.Contains(combined, "inappropriate ioctl for device") {
		return fmt.Errorf("%w: %w", credential.ErrCredentialStoreLocked, err)
	}
	if strings.Contains(combined, "no secret key") || strings.Contains(combined, "gpg") || isNotFoundErr(err) {
		return fmt.Errorf("%w: %w", credential.ErrCredentialStoreUnavailable, err)
	}

	return fmt.Errorf("pass %s failed: %w", action, err)
}

// passCommandEnv overrides inherited GPG interaction options for automation.
func passCommandEnv(ctx context.Context, extra []string) []string {
	if !credential.InteractionDisabled(ctx) {
		if len(extra) == 0 {
			return nil
		}
		return append(os.Environ(), extra...)
	}
	env := append(os.Environ(), extra...)
	filtered := make([]string, 0, len(env)+1)
	for _, entry := range env {
		if !strings.HasPrefix(entry, "PASSWORD_STORE_GPG_OPTS=") {
			filtered = append(filtered, entry)
		}
	}
	return append(filtered, "PASSWORD_STORE_GPG_OPTS=--batch --no-tty --pinentry-mode error")
}
