package utils

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"golang.org/x/term"
)

const (
	// RememberPolicyAsk 默认策略：交互时询问用户是否保存，非交互时不保存
	RememberPolicyAsk = "ask"
	// RememberPolicyAlways 总是保存凭据
	RememberPolicyAlways = "always"
	// RememberPolicyNever 从不保存凭据（会话级）
	RememberPolicyNever = "never"
)

// ValidateRememberPolicy 校验 remember 策略取值
func ValidateRememberPolicy(policy string) error {
	p := strings.ToLower(strings.TrimSpace(policy))
	if p == "" || p == RememberPolicyAsk || p == RememberPolicyAlways || p == RememberPolicyNever {
		return nil
	}
	return fmt.Errorf("invalid remember policy %q, expected one of: ask, always, never", policy)
}

// GetCredentialRegistry 根据配置构建只读凭据注册表（若未配置返回 nil）
func GetCredentialRegistry(cfg *config.Configuration) (*credential.Registry, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration is nil")
	}
	// A configuration without a credential section has no references to resolve.
	// Do not eagerly initialize the platform keyring: session-only connections
	// must work in headless environments where that keyring is unavailable.
	if cfg.Credential == nil {
		return nil, nil
	}
	return BuildCredentialRegistry(credentialConfigOrDefault(cfg))
}

func credentialConfigOrDefault(cfg *config.Configuration) *config.CredentialConfig {
	if cfg.Credential != nil {
		return cfg.Credential
	}
	return &config.CredentialConfig{
		DefaultStore:     "none",
		RememberPrompted: RememberPolicyAsk,
		Stores: map[string]config.StoreConfig{
			"none": {Type: config.StoreTypeNone},
		},
	}
}

// GetCredentialService 根据配置和存储仓库实例化凭据服务
func GetCredentialService(repo *config.Repository, cfg *config.Configuration) (*credential.Service, error) {
	return getCredentialService(repo, cfg, nil)
}

func getCredentialService(repo *config.Repository, cfg *config.Configuration, updater credential.ConfigUpdater) (*credential.Service, error) {

	if repo == nil {
		return nil, fmt.Errorf("configuration repository is nil")
	}
	if cfg == nil {
		return nil, fmt.Errorf("configuration is nil")
	}

	credCfg := credentialConfigOrDefault(cfg)

	registry, err := BuildCredentialRegistry(credCfg)
	if err != nil {
		return nil, fmt.Errorf("build credential registry: %w", err)
	}

	journalDir := os.Getenv("XOPS_JOURNAL_DIR")
	if journalDir == "" {
		configPath, _, pathErr := GetConfigFilePath()
		if pathErr != nil {
			return nil, fmt.Errorf("resolve journal directory: %w", pathErr)
		}
		journalDir = filepath.Join(filepath.Dir(configPath), "journals")
	}

	if err := os.MkdirAll(journalDir, 0700); err != nil {
		return nil, fmt.Errorf("create journal directory %q: %w", journalDir, err)
	}

	journalStore, err := credential.NewJournalStore(journalDir)
	if err != nil {
		return nil, fmt.Errorf("initialize journal store: %w", err)
	}
	if updater == nil {
		updater = repo.AsConfigUpdater()
	}
	return credential.NewService(registry, journalStore, updater, nil)
}

// ReadSecretFromReader 从指定的 Reader 流读取机密并去除末尾的换行符
func ReadSecretFromReader(r io.Reader) (string, error) {
	if r == nil {
		r = os.Stdin
	}
	const maxSecretSize = 65536 // 最大限制 64KB，防止失控或恶意输入
	data, err := io.ReadAll(io.LimitReader(r, maxSecretSize))
	if err != nil {
		return "", fmt.Errorf("read secret failed: %w", err)
	}
	secret := strings.TrimRight(string(data), "\r\n")
	if len(secret) == 0 {
		return "", errors.New("standard input is empty")
	}
	return secret, nil
}

// ReadSecretFromStdin 从标准输入流读取机密并去除末尾的换行符
func ReadSecretFromStdin() (string, error) {
	return ReadSecretFromReader(os.Stdin)
}

// WarnFlagDeprecated 输出统一的 CLI 参数废弃警告
func WarnFlagDeprecated(flagName, replacement string) {
	msg := i18n.Tf("warn_flag_deprecated", map[string]any{
		"Flag":        flagName,
		"Replacement": replacement,
	})
	if msg == "" || msg == "warn_flag_deprecated" {
		msg = fmt.Sprintf("Flag --%s is deprecated and will be removed in the next stable release. Please use %s.", flagName, replacement)
	}
	logger.PrintWarn(msg)
}

// EffectiveRememberPolicy applies command override, configuration, then ask.
func EffectiveRememberPolicy(override string, cfg *config.Configuration) string {
	policy := strings.ToLower(strings.TrimSpace(override))
	if policy == "" && cfg != nil && cfg.Credential != nil {
		policy = cfg.Credential.RememberPrompted
	}
	if policy == "" {
		return RememberPolicyAsk
	}
	return policy
}

// ShouldRememberConfiguredCredential skips confirmation when persistence is
// disabled or no writable default store is configured, without probing stores.
func ShouldRememberConfiguredCredential(policy, targetName string, cfg *config.Configuration) bool {
	return cfg.CanRememberCredentials() && ShouldRememberCredential(policy, targetName)
}

// ShouldRememberCredential applies the policy, asking only on a terminal.
func ShouldRememberCredential(policy string, targetName string) bool {
	p := strings.ToLower(strings.TrimSpace(policy))
	switch p {
	case RememberPolicyAlways:
		return true
	case RememberPolicyNever:
		return false
	case RememberPolicyAsk:
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return false
		}
		ok, err := AskConfirmation(fmt.Sprintf("Save credential for %q?", targetName))
		if err != nil {
			return false
		}
		return ok
	case "":
		return ShouldRememberCredential(RememberPolicyAsk, targetName)
	default:
		return false
	}
}
