package credentialhelper

import (
	"fmt"
	"strings"
	"time"
)

const (
	// DefaultSystemHelperCommand 是系统密钥库 helper 的默认二进制名称。
	DefaultSystemHelperCommand = "xops-credential-system"
)

// SystemStoreConfig 包含系统密钥库后端的配置选项。
type SystemStoreConfig struct {
	Command  string
	Args     []string
	Env      []string
	Timeout  time.Duration
	ReadOnly bool
}

// SystemStore 封装操作系统原生密钥库的凭据存储。
type SystemStore struct {
	*HelperStore
}

// NewSystemStore 创建系统密钥库存储实例。
func NewSystemStore(storeID string, cfg SystemStoreConfig) (*SystemStore, error) {
	if strings.TrimSpace(storeID) == "" {
		storeID = "system"
	}

	cmdPath := cfg.Command
	if strings.TrimSpace(cmdPath) == "" {
		defaultCmd, err := resolveDefaultSystemHelper()
		if err != nil {
			return nil, err
		}
		cmdPath = defaultCmd
	}

	opts := ProcessOptions{
		Command: cmdPath,
		Args:    cfg.Args,
		Env:     cfg.Env,
		Timeout: cfg.Timeout,
	}

	hs, err := NewHelperStore(storeID, opts, cfg.ReadOnly)
	if err != nil {
		return nil, fmt.Errorf("initialize system credential store: %w", err)
	}

	return &SystemStore{HelperStore: hs}, nil
}

// CheckSystemAvailability 检查当前平台系统密钥库环境是否满足可用性前置要求。
func CheckSystemAvailability() error {
	return checkPlatformSystemAvailability()
}
