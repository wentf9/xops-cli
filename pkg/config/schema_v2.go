package config

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
	"gopkg.in/yaml.v3"
)

// StoreType 定义受支持的凭据存储后端类型。
type StoreType string

const (
	StoreTypeSystem StoreType = "system"
	StoreTypePass   StoreType = "pass"
	StoreTypeHelper StoreType = "helper"
	StoreTypeNone   StoreType = "none"
)

// StoreConfig 描述单个凭据存储后端的连接与运行配置。
type StoreConfig struct {
	Type     StoreType     `yaml:"type"`
	Timeout  time.Duration `yaml:"timeout"`
	CacheTTL time.Duration `yaml:"cache_ttl"`
	Prefix   string        `yaml:"prefix,omitempty"`
	Command  string        `yaml:"command,omitempty"`
	Args     []string      `yaml:"args,omitempty"`
	ReadOnly bool          `yaml:"read_only,omitempty"`
}

type rawStoreConfig struct {
	Type     StoreType `yaml:"type"`
	Timeout  string    `yaml:"timeout"`
	CacheTTL string    `yaml:"cache_ttl"`
	Prefix   string    `yaml:"prefix,omitempty"`
	Command  string    `yaml:"command,omitempty"`
	Args     []string  `yaml:"args,omitempty"`
	ReadOnly bool      `yaml:"read_only,omitempty"`
}

// UnmarshalYAML 自定义反序列化，支持 "5s"、"10m" 格式的超时与缓存 TTL 配置，并严格校验未知字段。
func (s *StoreConfig) UnmarshalYAML(value *yaml.Node) error {
	if value == nil {
		return fmt.Errorf("%w: store config node is nil", ErrSchemaValidation)
	}
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("%w: expected mapping for store config", ErrSchemaValidation)
	}

	knownFields := map[string]struct{}{
		"type":      {},
		"timeout":   {},
		"cache_ttl": {},
		"prefix":    {},
		"command":   {},
		"args":      {},
		"read_only": {},
	}

	for i := 0; i < len(value.Content); i += 2 {
		fieldName := value.Content[i].Value
		if _, ok := knownFields[fieldName]; !ok {
			return fmt.Errorf("%w: unknown field %q in store configuration", ErrSchemaValidation, fieldName)
		}
	}

	var raw rawStoreConfig
	if err := value.Decode(&raw); err != nil {
		return fmt.Errorf("%w: decode store config: %w", ErrSchemaValidation, err)
	}

	s.Type = raw.Type
	s.Prefix = raw.Prefix
	s.Command = raw.Command
	s.Args = slices.Clone(raw.Args)
	s.ReadOnly = raw.ReadOnly

	if strings.TrimSpace(raw.Timeout) != "" {
		d, err := time.ParseDuration(raw.Timeout)
		if err != nil {
			return fmt.Errorf("invalid timeout %q: %w", raw.Timeout, err)
		}
		s.Timeout = d
	}

	if strings.TrimSpace(raw.CacheTTL) != "" {
		d, err := time.ParseDuration(raw.CacheTTL)
		if err != nil {
			return fmt.Errorf("invalid cache_ttl %q: %w", raw.CacheTTL, err)
		}
		s.CacheTTL = d
	}

	return nil
}

// CredentialConfig 描述 Schema v2 顶层的凭据全局配置。
type CredentialConfig struct {
	DefaultStore     string                 `yaml:"default_store"`
	RememberPrompted string                 `yaml:"remember_prompted,omitempty"` // "ask", "always", "never"
	Stores           map[string]StoreConfig `yaml:"stores"`
}

// Clone 返回 CredentialConfig 的深拷贝。
func (c *CredentialConfig) Clone() *CredentialConfig {
	if c == nil {
		return nil
	}
	cloned := &CredentialConfig{
		DefaultStore:     c.DefaultStore,
		RememberPrompted: c.RememberPrompted,
		Stores:           make(map[string]StoreConfig, len(c.Stores)),
	}
	for k, v := range c.Stores {
		sc := v
		sc.Args = slices.Clone(v.Args)
		cloned.Stores[k] = sc
	}
	return cloned
}

// IdentityV2 对应 Schema v2 中的认证身份配置，不含任何明文凭据。
type IdentityV2 struct {
	User             string          `yaml:"user"`
	KeyPath          string          `yaml:"key_path,omitempty"`
	KeyFingerprint   string          `yaml:"key_fingerprint,omitempty"`
	LoginPasswordRef *credential.Ref `yaml:"login_password_ref,omitempty"`
	PassphraseRef    *credential.Ref `yaml:"passphrase_ref,omitempty"`
	AuthType         string          `yaml:"auth_type"`
}

// NodeV2 对应 Schema v2 中的节点配置，提权密码使用引用模型。
type NodeV2 struct {
	Alias                 []string        `yaml:"alias,omitempty"`
	Tags                  []string        `yaml:"tags,omitempty"`
	HostRef               string          `yaml:"host_ref"`
	IdentityRef           string          `yaml:"identity_ref"`
	ProxyJump             string          `yaml:"proxy_jump,omitempty"`
	SudoMode              models.SudoMode `yaml:"sudo_mode"`
	PrivilegePasswordRef  *credential.Ref `yaml:"privilege_password_ref,omitempty"`
	PasswordPromptPattern string          `yaml:"password_prompt_pattern,omitempty"`
}

// ConfigurationV2 是 Schema v2 的顶级规范配置 DTO。
// 【安全红线】本结构及反序列化过程中绝不包含任何密码明文字段。
type ConfigurationV2 struct {
	SchemaVersion         int                    `yaml:"schema_version"`
	Credential            CredentialConfig       `yaml:"credential"`
	Identities            map[string]IdentityV2  `yaml:"identities"`
	Hosts                 map[string]models.Host `yaml:"hosts"`
	Nodes                 map[string]NodeV2      `yaml:"nodes"`
	Guardrail             *GuardrailConfig       `yaml:"guardrail,omitempty"`
	PasswordPromptPattern string                 `yaml:"password_prompt_pattern,omitempty"`
}

// ValidateV2 对 ConfigurationV2 进行全面且严格的合法性校验。
func ValidateV2(cfg *ConfigurationV2) error {
	if cfg == nil {
		return fmt.Errorf("%w: configuration is nil", ErrSchemaValidation)
	}
	if cfg.SchemaVersion != 2 {
		return fmt.Errorf("%w: expected schema_version 2, got %d", ErrSchemaValidation, cfg.SchemaVersion)
	}

	if err := validateCredentialConfig(&cfg.Credential); err != nil {
		return err
	}

	for idName, id := range cfg.Identities {
		if err := validateIdentityRefs(idName, id, cfg.Credential.Stores); err != nil {
			return err
		}
	}

	for nodeName, node := range cfg.Nodes {
		if err := validateNodeRefs(nodeName, node, cfg); err != nil {
			return err
		}
	}

	return nil
}

func validateCredentialConfig(cred *CredentialConfig) error {
	if cred.DefaultStore != "" {
		if _, exists := cred.Stores[cred.DefaultStore]; !exists {
			return fmt.Errorf("%w: default_store %q not found in defined stores",
				ErrSchemaValidation, cred.DefaultStore)
		}
	}

	switch cred.RememberPrompted {
	case "", "ask", "always", "never":
	default:
		return fmt.Errorf("%w: invalid remember_prompted value %q (must be ask, always, or never)",
			ErrSchemaValidation, cred.RememberPrompted)
	}

	for storeID, storeCfg := range cred.Stores {
		if err := validateStoreConfig(storeID, storeCfg); err != nil {
			return err
		}
	}
	return nil
}

func validateStoreConfig(storeID string, storeCfg StoreConfig) error {
	if strings.TrimSpace(storeID) == "" {
		return fmt.Errorf("%w: storeID cannot be empty", ErrSchemaValidation)
	}
	if strings.ContainsAny(storeID, "/\\ \t\r\n\x00") {
		return fmt.Errorf("%w: storeID %q contains invalid characters", ErrSchemaValidation, storeID)
	}

	switch storeCfg.Type {
	case StoreTypeSystem, StoreTypePass, StoreTypeHelper, StoreTypeNone:
	default:
		return fmt.Errorf("%w: store %q has invalid type %q", ErrSchemaValidation, storeID, storeCfg.Type)
	}

	if storeCfg.Type == StoreTypeHelper {
		if strings.TrimSpace(storeCfg.Command) == "" {
			return fmt.Errorf("%w: helper store %q requires non-empty command", ErrSchemaValidation, storeID)
		}
		if strings.ContainsAny(storeCfg.Command, ";|&`$\n") {
			return fmt.Errorf("%w: helper store %q command contains forbidden shell characters",
				ErrSchemaValidation, storeID)
		}
	}

	if storeCfg.Timeout < 0 {
		return fmt.Errorf("%w: store %q timeout cannot be negative", ErrSchemaValidation, storeID)
	}
	if storeCfg.CacheTTL < 0 {
		return fmt.Errorf("%w: store %q cache_ttl cannot be negative", ErrSchemaValidation, storeID)
	}
	return nil
}

func validateIdentityRefs(idName string, id IdentityV2, stores map[string]StoreConfig) error {
	if id.LoginPasswordRef != nil {
		if err := id.LoginPasswordRef.Validate(); err != nil {
			return fmt.Errorf("%w: identity %q login_password_ref invalid: %w", ErrSchemaValidation, idName, err)
		}
		if !id.LoginPasswordRef.IsEmpty() {
			if _, ok := stores[id.LoginPasswordRef.StoreID]; !ok {
				return fmt.Errorf("%w: identity %q login_password_ref store %q not configured",
					ErrSchemaValidation, idName, id.LoginPasswordRef.StoreID)
			}
		}
	}

	if id.PassphraseRef != nil {
		if err := id.PassphraseRef.Validate(); err != nil {
			return fmt.Errorf("%w: identity %q passphrase_ref invalid: %w", ErrSchemaValidation, idName, err)
		}
		if !id.PassphraseRef.IsEmpty() {
			if _, ok := stores[id.PassphraseRef.StoreID]; !ok {
				return fmt.Errorf("%w: identity %q passphrase_ref store %q not configured",
					ErrSchemaValidation, idName, id.PassphraseRef.StoreID)
			}
			if strings.TrimSpace(id.KeyFingerprint) == "" {
				return fmt.Errorf("%w: identity %q with passphrase_ref must specify key_fingerprint",
					ErrSchemaValidation, idName)
			}
			if strings.ContainsAny(id.KeyFingerprint, " \t\r\n\x00") {
				return fmt.Errorf("%w: identity %q has invalid key_fingerprint %q",
					ErrSchemaValidation, idName, id.KeyFingerprint)
			}
		}
	}
	return nil
}

func validateNodeRefs(nodeName string, node NodeV2, cfg *ConfigurationV2) error {
	if node.HostRef != "" {
		if _, exists := cfg.Hosts[node.HostRef]; !exists {
			return fmt.Errorf("%w: node %q references non-existent host %q", ErrSchemaValidation, nodeName, node.HostRef)
		}
	}
	if node.IdentityRef != "" {
		if _, exists := cfg.Identities[node.IdentityRef]; !exists {
			return fmt.Errorf("%w: node %q references non-existent identity %q", ErrSchemaValidation, nodeName, node.IdentityRef)
		}
	}

	if node.PrivilegePasswordRef != nil {
		if err := node.PrivilegePasswordRef.Validate(); err != nil {
			return fmt.Errorf("%w: node %q privilege_password_ref invalid: %w", ErrSchemaValidation, nodeName, err)
		}
		if !node.PrivilegePasswordRef.IsEmpty() {
			if _, ok := cfg.Credential.Stores[node.PrivilegePasswordRef.StoreID]; !ok {
				return fmt.Errorf("%w: node %q privilege_password_ref store %q not configured",
					ErrSchemaValidation, nodeName, node.PrivilegePasswordRef.StoreID)
			}
		}
	}
	return nil
}

// UnmarshalV2 解析并严格校验 Schema v2 YAML 配置。
// 如果 YAML 中含有历史明文机密字段（password/passphrase/su_pwd），坚决拒绝并返回错误。
func UnmarshalV2(data []byte) (*ConfigurationV2, error) {
	// 严格模式安全检查：禁止任何明文凭据键名出现
	if err := checkForbiddenPlaintextFields(data); err != nil {
		return nil, err
	}

	var cfg ConfigurationV2
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%w: decode yaml: %w", ErrSchemaValidation, err)
	}

	if err := ValidateV2(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func checkForbiddenPlaintextFields(data []byte) error {
	var generic map[string]interface{}
	if err := yaml.Unmarshal(data, &generic); err != nil {
		return fmt.Errorf("%w: inspect yaml structure: %w", ErrSchemaValidation, err)
	}

	// 检查 identities 是否包含 password 或 passphrase
	if identitiesRaw, ok := generic["identities"].(map[string]interface{}); ok {
		for idName, val := range identitiesRaw {
			if fields, ok := val.(map[string]interface{}); ok {
				if _, hasPwd := fields["password"]; hasPwd {
					return fmt.Errorf("%w: identity %q contains forbidden plaintext field 'password' in schema v2",
						ErrSchemaValidation, idName)
				}
				if _, hasPassphrase := fields["passphrase"]; hasPassphrase {
					return fmt.Errorf("%w: identity %q contains forbidden plaintext field 'passphrase' in schema v2",
						ErrSchemaValidation, idName)
				}
			}
		}
	}

	// 检查 nodes 是否包含 su_pwd
	if nodesRaw, ok := generic["nodes"].(map[string]interface{}); ok {
		for nodeName, val := range nodesRaw {
			if fields, ok := val.(map[string]interface{}); ok {
				if _, hasSuPwd := fields["su_pwd"]; hasSuPwd {
					return fmt.Errorf("%w: node %q contains forbidden plaintext field 'su_pwd' in schema v2",
						ErrSchemaValidation, nodeName)
				}
			}
		}
	}

	return nil
}

// ToV2 将内存中的 Configuration 转换为 Schema v2 DTO。
// 如果包含明文机密，将拒绝转换，确保安全。
func (c *Configuration) ToV2() (*ConfigurationV2, error) {
	if c == nil {
		return nil, fmt.Errorf("configuration is nil")
	}

	v2 := &ConfigurationV2{
		SchemaVersion:         2,
		Identities:            make(map[string]IdentityV2),
		Hosts:                 make(map[string]models.Host),
		Nodes:                 make(map[string]NodeV2),
		PasswordPromptPattern: c.PasswordPromptPattern,
	}

	if c.Credential != nil {
		v2.Credential = *c.Credential.Clone()
	} else {
		v2.Credential = CredentialConfig{
			Stores: make(map[string]StoreConfig),
		}
	}

	if c.Guardrail != nil {
		v2.Guardrail = cloneGuardrail(c.Guardrail)
	}

	if c.Hosts != nil {
		for _, key := range c.Hosts.Keys() {
			if h, ok := c.Hosts.Get(key); ok {
				v2.Hosts[key] = cloneHost(h)
			}
		}
	}

	if c.Identities != nil {
		for _, key := range c.Identities.Keys() {
			if id, ok := c.Identities.Get(key); ok {
				if id.Password != "" || id.Passphrase != "" {
					return nil, fmt.Errorf("%w: identity %q contains plaintext secret, migrate credentials first",
						ErrSchemaValidation, key)
				}
				v2.Identities[key] = IdentityV2{
					User:             id.User,
					KeyPath:          id.KeyPath,
					KeyFingerprint:   id.KeyFingerprint,
					LoginPasswordRef: id.LoginPasswordRef.Clone(),
					PassphraseRef:    id.PassphraseRef.Clone(),
					AuthType:         id.AuthType,
				}
			}
		}
	}

	if c.Nodes != nil {
		for _, key := range c.Nodes.Keys() {
			if n, ok := c.Nodes.Get(key); ok {
				if n.SuPwd != "" {
					return nil, fmt.Errorf("%w: node %q contains plaintext su_pwd, migrate credentials first",
						ErrSchemaValidation, key)
				}
				v2.Nodes[key] = NodeV2{
					Alias:                 slices.Clone(n.Alias),
					Tags:                  slices.Clone(n.Tags),
					HostRef:               n.HostRef,
					IdentityRef:           n.IdentityRef,
					ProxyJump:             n.ProxyJump,
					SudoMode:              n.SudoMode,
					PrivilegePasswordRef:  n.PrivilegePasswordRef.Clone(),
					PasswordPromptPattern: n.PasswordPromptPattern,
				}
			}
		}
	}

	if err := ValidateV2(v2); err != nil {
		return nil, err
	}

	return v2, nil
}

// FromV2 将 Schema v2 DTO 转换为内存中的 Configuration 实体。
func FromV2(v2 *ConfigurationV2) (*Configuration, error) {
	if err := ValidateV2(v2); err != nil {
		return nil, err
	}

	cfg := &Configuration{
		SchemaVersion:         2,
		Credential:            v2.Credential.Clone(),
		Identities:            concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:                 concurrent.NewMap[string, models.Host](concurrent.HashString),
		Nodes:                 concurrent.NewMap[string, models.Node](concurrent.HashString),
		Guardrail:             cloneGuardrail(v2.Guardrail),
		PasswordPromptPattern: v2.PasswordPromptPattern,
	}

	for k, h := range v2.Hosts {
		cfg.Hosts.Set(k, cloneHost(h))
	}

	for k, id := range v2.Identities {
		cfg.Identities.Set(k, models.Identity{
			User:             id.User,
			KeyPath:          id.KeyPath,
			KeyFingerprint:   id.KeyFingerprint,
			LoginPasswordRef: id.LoginPasswordRef.Clone(),
			PassphraseRef:    id.PassphraseRef.Clone(),
			AuthType:         id.AuthType,
		})
	}

	for k, n := range v2.Nodes {
		cfg.Nodes.Set(k, models.Node{
			Alias:                 slices.Clone(n.Alias),
			Tags:                  slices.Clone(n.Tags),
			HostRef:               n.HostRef,
			IdentityRef:           n.IdentityRef,
			ProxyJump:             n.ProxyJump,
			SudoMode:              n.SudoMode,
			PrivilegePasswordRef:  n.PrivilegePasswordRef.Clone(),
			PasswordPromptPattern: n.PasswordPromptPattern,
		})
	}

	return cfg, nil
}
