package config

import (
	"errors"
	"fmt"
	"os"

	"github.com/wentf9/xops-cli/pkg/crypto"
	"gopkg.in/yaml.v3"
)

// ReadMCPSettings reads only service settings and audit policy, without loading
// credentials, acquiring writable config locks or migrating legacy secrets.
func ReadMCPSettings(path string) (*MCPConfig, *GuardrailConfig, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read MCP configuration settings: %w", err)
	}
	var settings struct {
		MCP       *MCPConfig       `yaml:"mcp"`
		Guardrail *GuardrailConfig `yaml:"guardrail"`
	}
	if err := yaml.Unmarshal(data, &settings); err != nil {
		// YAML's original diagnostic may contain scalar values from a legacy
		// secret. Return the classified error without reflecting configuration.
		return nil, nil, fmt.Errorf("%w: invalid MCP service configuration", ErrSchemaValidation)
	}
	return settings.MCP.Clone(), cloneGuardrail(settings.Guardrail), nil
}

// ReadOnlyConfiguration decodes one atomically published configuration file.
// Legacy decryption uses an existing key only; it never creates keys, upgrades
// schemas or writes encrypted replacements for plaintext credentials.
func ReadOnlyConfiguration(path, keyPath string) (*Configuration, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read configuration without migration: %w", err)
	}
	version, err := DetectSchemaVersion(data)
	if err != nil {
		return nil, err
	}
	if version == 2 {
		dto, err := UnmarshalV2(data)
		if err != nil {
			return nil, err
		}
		return FromV2(dto)
	}
	cfg, err := decodeMigrationLegacy(data)
	if err != nil {
		return nil, err
	}
	var crypter *crypto.Crypter
	if hasEncryptedConfigurationSecrets(cfg) {
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("read existing configuration key: %w", err)
		}
		crypter, err = crypto.NewCrypter(key)
		if err != nil {
			return nil, fmt.Errorf("initialize read-only configuration decryption: %w", err)
		}
	}
	if _, err := decryptIdentities(crypter, cfg); err != nil {
		return nil, err
	}
	if _, err := decryptNodes(crypter, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func hasEncryptedConfigurationSecrets(cfg *Configuration) bool {
	for _, key := range cfg.Identities.Keys() {
		identity, _ := cfg.Identities.Get(key)
		if crypto.IsEncrypted(identity.Password) || crypto.IsEncrypted(identity.Passphrase) {
			return true
		}
	}
	for _, key := range cfg.Nodes.Keys() {
		node, _ := cfg.Nodes.Get(key)
		if crypto.IsEncrypted(node.SuPwd) {
			return true
		}
	}
	return false
}
