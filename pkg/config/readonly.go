package config

import (
	"errors"
	"fmt"
	"os"

	corepolicy "github.com/wentf9/xops-cli/core/mcp/policy"
	"gopkg.in/yaml.v3"
)

// ReadMCPSettings reads only service settings and audit policy, without loading
// credentials, acquiring writable config locks or migrating legacy secrets.
func ReadMCPSettings(path string) (*MCPConfig, *corepolicy.Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read MCP configuration settings: %w", err)
	}
	version, err := DetectSchemaVersion(data)
	if err != nil {
		if errors.Is(err, ErrUnsupportedSchemaVersion) {
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("%w: invalid MCP service configuration", ErrSchemaValidation)
	}
	if err := ValidateRuntimeSchema(version); err != nil {
		return nil, nil, err
	}
	var settings struct {
		MCP       *MCPConfig         `yaml:"mcp"`
		Guardrail *corepolicy.Config `yaml:"guardrail"`
	}
	if err := yaml.Unmarshal(data, &settings); err != nil {
		// YAML's original diagnostic may contain scalar values from a legacy
		// secret. Return the classified error without reflecting configuration.
		return nil, nil, fmt.Errorf("%w: invalid MCP service configuration", ErrSchemaValidation)
	}
	return settings.MCP.Clone(), cloneGuardrail(settings.Guardrail), nil
}

// ReadOnlyConfiguration reads Schema v2 without acquiring writable locks.
// The legacy key parameter is ignored; only the explicit migrator decrypts v1.
func ReadOnlyConfiguration(path, _ string) (*Configuration, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read configuration without migration: %w", err)
	}
	version, err := DetectSchemaVersion(data)
	if err != nil {
		return nil, err
	}
	if err := ValidateRuntimeSchema(version); err != nil {
		return nil, err
	}
	dto, err := UnmarshalV2(data)
	if err != nil {
		return nil, err
	}
	return FromV2(dto)
}
