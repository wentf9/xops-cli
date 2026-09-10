package config

import (
	"fmt"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/internal/credentialhelper"
	"github.com/wentf9/xops-cli/pkg/credential"
)

// BuildStore 根据 StoreConfig 配置实例化对应的凭据存储。
// 若配置了 cache_ttl > 0，会自动挂载有界内存凭据缓存装饰器。
func BuildStore(storeID string, cfg StoreConfig) (credential.Store, error) {
	if strings.TrimSpace(storeID) == "" {
		return nil, fmt.Errorf("storeID cannot be empty")
	}

	var baseStore credential.Store
	var err error

	switch cfg.Type {
	case StoreTypeEncryptedFile:
		return nil, fmt.Errorf("%w: encrypted-file requires an owned credential runtime", credential.ErrCredentialStoreUnavailable)
	case StoreTypeNone:
		baseStore = credential.NewNoneStore()

	case StoreTypeHelper:
		if strings.TrimSpace(cfg.Command) == "" {
			return nil, fmt.Errorf("%w: helper store %q requires non-empty command", ErrSchemaValidation, storeID)
		}
		opts := credentialhelper.ProcessOptions{
			Command:        cfg.Command,
			NonInteractive: cfg.NonInteractive,
			Args:           cfg.Args,
			Timeout:        cfg.Timeout,
		}
		baseStore, err = credentialhelper.NewHelperStore(storeID, opts, cfg.ReadOnly)
		if err != nil {
			return nil, fmt.Errorf("initialize helper store %q: %w", storeID, err)
		}

	case StoreTypePass:
		passCfg := credentialhelper.PassStoreConfig{
			Prefix:         cfg.Prefix,
			Command:        cfg.Command,
			NonInteractive: cfg.NonInteractive,
			Args:           cfg.Args,
			Timeout:        cfg.Timeout,
			ReadOnly:       cfg.ReadOnly,
		}
		baseStore, err = credentialhelper.NewPassStore(storeID, passCfg)
		if err != nil {
			return nil, fmt.Errorf("initialize pass store %q: %w", storeID, err)
		}

	case StoreTypeSystem:
		sysCfg := credentialhelper.SystemStoreConfig{
			Command:        cfg.Command,
			NonInteractive: cfg.NonInteractive,
			Args:           cfg.Args,
			Timeout:        cfg.Timeout,
			ReadOnly:       cfg.ReadOnly,
		}
		baseStore, err = credentialhelper.NewSystemStore(storeID, sysCfg)
		if err != nil {
			return nil, fmt.Errorf("initialize system store %q: %w", storeID, err)
		}

	default:
		return nil, fmt.Errorf("%w: unsupported store type %q for store %q", ErrSchemaValidation, cfg.Type, storeID)
	}

	// 若配置了大于 0 的 cache_ttl，挂载有界凭据缓存
	if cfg.CacheTTL > 0 {
		cache := credential.NewCache(credential.CacheOptions{
			Capacity:   credential.DefaultCacheCapacity,
			DefaultTTL: cfg.CacheTTL,
		})
		return credential.NewCachedStore(baseStore, cache), nil
	}

	return baseStore, nil
}

// BuildRegistryFromConfig 遍历 CredentialConfig 中声明的所有 stores 并构建已注册的 Registry。
func BuildRegistryFromConfig(credCfg *CredentialConfig) (*credential.Registry, error) {
	if credCfg == nil {
		return nil, fmt.Errorf("credential config is nil")
	}

	return buildRegistry(credCfg, nil)
}

func buildRegistry(credCfg *CredentialConfig, files *EncryptedRuntime) (*credential.Registry, error) {
	reg := credential.NewRegistry()
	for storeID, storeCfg := range credCfg.Stores {
		if err := validateStoreConfig(storeID, storeCfg); err != nil {
			return nil, err
		}
		storeCfg.Args = slices.Clone(storeCfg.Args)
		var st credential.Store = &lazyStore{storeID: storeID, config: storeCfg}
		if storeCfg.Type == StoreTypeEncryptedFile && files != nil {
			var err error
			st, err = files.backend(storeID, storeCfg)
			if err != nil {
				return nil, err
			}
		}
		if err := reg.Register(storeID, st); err != nil {
			return nil, fmt.Errorf("register store %q: %w", storeID, err)
		}
	}

	return reg, nil
}
