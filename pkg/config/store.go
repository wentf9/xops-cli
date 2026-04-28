package config

import (
	"os"
	"sync"

	"github.com/wentf9/xops-cli/pkg/crypto"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
	"github.com/wentf9/xops-cli/pkg/utils/file"
	"gopkg.in/yaml.v3"
)

// Store 定义了配置存储和持久化的接口
type Store interface {
	Load() (*Configuration, error)
	Save(cfg *Configuration) error
}

type defaultStore struct {
	Path    string
	KeyPath string // 用于加解密配置文件中的敏感字段
	mu      sync.Mutex
}

func (s *defaultStore) Load() (*Configuration, error) {
	config := Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	// 1. 读取文件
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return &config, nil
	}
	// 2. yaml.Unmarshal
	if err = yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	// 3. 初始化 Crypter 并解密敏感字段
	key, err := crypto.LoadOrGenerateKey(s.KeyPath)
	if err != nil {
		return nil, err
	}
	crypter, err := crypto.NewCrypter(key)
	if err != nil {
		return nil, err
	}
	migratedIdentities := decryptIdentities(crypter, &config)
	migratedNodes := decryptNodes(crypter, &config)
	// 若配置文件中存在明文敏感字段，立即加密回写（一次性迁移）
	if migratedIdentities || migratedNodes {
		_ = s.Save(&config)
	}
	return &config, nil
}

// decryptIdentities 解密所有 Identity 中的 Password 和 Passphrase 字段。
// 返回 true 表示发现了明文值（需要触发迁移保存）。
func decryptIdentities(crypter *crypto.Crypter, config *Configuration) (migrated bool) {
	for _, name := range config.Identities.Keys() {
		identity, _ := config.Identities.Get(name)
		changed := false
		if identity.Password != "" {
			if crypto.IsEncrypted(identity.Password) {
				if plain, err := crypter.Decrypt(identity.Password); err == nil {
					identity.Password = plain
					changed = true
				}
			} else {
				migrated = true // 明文，需加密回写
			}
		}
		if identity.Passphrase != "" {
			if crypto.IsEncrypted(identity.Passphrase) {
				if plain, err := crypter.Decrypt(identity.Passphrase); err == nil {
					identity.Passphrase = plain
					changed = true
				}
			} else {
				migrated = true
			}
		}
		if changed {
			config.Identities.Set(name, identity)
		}
	}
	return migrated
}

// decryptNodes 解密所有 Node 中的 SuPwd 字段。
// 返回 true 表示发现了明文值（需要触发迁移保存）。
func decryptNodes(crypter *crypto.Crypter, config *Configuration) (migrated bool) {
	for _, name := range config.Nodes.Keys() {
		node, _ := config.Nodes.Get(name)
		if node.SuPwd != "" {
			if crypto.IsEncrypted(node.SuPwd) {
				if plain, err := crypter.Decrypt(node.SuPwd); err == nil {
					node.SuPwd = plain
					config.Nodes.Set(name, node)
				}
			} else {
				migrated = true // 明文，需加密回写
			}
		}
	}
	return migrated
}

func (s *defaultStore) Save(cfg *Configuration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// 初始化 Crypter
	key, err := crypto.LoadOrGenerateKey(s.KeyPath)
	if err != nil {
		return err
	}
	crypter, err := crypto.NewCrypter(key)
	if err != nil {
		return err
	}

	// 加密敏感字段，记录原始值，序列化后立即恢复（防止内存被污染）
	origPasswords, origPassphrases := encryptIdentities(crypter, cfg)
	origSuPwds := encryptNodes(crypter, cfg)

	data, err := yaml.Marshal(cfg)

	// 无论序列化是否成功都恢复内存中的明文
	restoreIdentities(cfg, origPasswords, origPassphrases)
	restoreNodes(cfg, origSuPwds)

	if err != nil {
		return err
	}
	return file.CreateFileRecursive(s.Path, data, 0600)
}

func encryptIdentities(crypter *crypto.Crypter, cfg *Configuration) (origPasswords, origPassphrases map[string]string) {
	origPasswords = make(map[string]string)
	origPassphrases = make(map[string]string)
	for _, name := range cfg.Identities.Keys() {
		identity, _ := cfg.Identities.Get(name)
		if identity.Password != "" && !crypto.IsEncrypted(identity.Password) {
			origPasswords[name] = identity.Password
			if enc, err := crypter.Encrypt(identity.Password); err == nil {
				identity.Password = enc
			}
		}
		if identity.Passphrase != "" && !crypto.IsEncrypted(identity.Passphrase) {
			origPassphrases[name] = identity.Passphrase
			if enc, err := crypter.Encrypt(identity.Passphrase); err == nil {
				identity.Passphrase = enc
			}
		}
		cfg.Identities.Set(name, identity)
	}
	return origPasswords, origPassphrases
}

func encryptNodes(crypter *crypto.Crypter, cfg *Configuration) map[string]string {
	origSuPwds := make(map[string]string)
	for _, name := range cfg.Nodes.Keys() {
		node, _ := cfg.Nodes.Get(name)
		if node.SuPwd != "" && !crypto.IsEncrypted(node.SuPwd) {
			origSuPwds[name] = node.SuPwd
			if enc, err := crypter.Encrypt(node.SuPwd); err == nil {
				node.SuPwd = enc
				cfg.Nodes.Set(name, node)
			}
		}
	}
	return origSuPwds
}

func restoreIdentities(cfg *Configuration, origPasswords, origPassphrases map[string]string) {
	for name, plain := range origPasswords {
		if identity, ok := cfg.Identities.Get(name); ok {
			identity.Password = plain
			cfg.Identities.Set(name, identity)
		}
	}
	for name, plain := range origPassphrases {
		if identity, ok := cfg.Identities.Get(name); ok {
			identity.Passphrase = plain
			cfg.Identities.Set(name, identity)
		}
	}
}

func restoreNodes(cfg *Configuration, origSuPwds map[string]string) {
	for name, plain := range origSuPwds {
		if node, ok := cfg.Nodes.Get(name); ok {
			node.SuPwd = plain
			cfg.Nodes.Set(name, node)
		}
	}
}

// NewDefaultStore 创建一个默认的文件系统配置存储实例
func NewDefaultStore(path string, keyPath string) Store {
	return &defaultStore{
		Path:    path,
		KeyPath: keyPath,
	}
}
