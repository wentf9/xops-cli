package config

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

// ErrUnsupportedSchemaVersion 表示不支持的配置文件 schema_version。
var ErrUnsupportedSchemaVersion = errors.New("unsupported schema version")

// ErrSchemaValidation 表示配置模式校验失败。
var ErrSchemaValidation = errors.New("schema validation failed")

// versionDetector 用于从 YAML 中提取顶层的 schema_version 字段。
type versionDetector struct {
	SchemaVersion *int `yaml:"schema_version"`
}

// DetectSchemaVersion 探测 YAML 字节流的配置模式版本。
// 如果没有显式指定 schema_version，按 Schema v1 处理（返回 1）。
// 检测器为显式迁移保留 v1 识别；普通加载另由 ValidateRuntimeSchema 限制为 v2。
func DetectSchemaVersion(data []byte) (int, error) {
	if len(data) == 0 {
		return 1, nil
	}

	var detector versionDetector
	if err := yaml.Unmarshal(data, &detector); err != nil {
		return 0, fmt.Errorf("detect schema version: %w", err)
	}

	if detector.SchemaVersion == nil {
		return 1, nil
	}

	version := *detector.SchemaVersion
	switch version {
	case 1, 2:
		return version, nil
	default:
		return version, fmt.Errorf("%w: version %d", ErrUnsupportedSchemaVersion, version)
	}
}

// ErrLegacyConfiguration marks configurations retired after the v0.12.0 and
// v0.13.0 compatibility releases. Only explicit migration may read their secrets.
var ErrLegacyConfiguration = errors.New("schema v1 compatibility ended after v0.13.0; run xops credential migrate --dry-run --to <store>, then xops credential migrate --to <store>")

// ValidateRuntimeSchema enforces the ordinary runtime policy independently of
// format detection, which must continue to recognize v1 for explicit migration.
func ValidateRuntimeSchema(version int) error {
	if version == 2 {
		return nil
	}
	if version == 1 {
		return fmt.Errorf("%w: %w", ErrUnsupportedSchemaVersion, ErrLegacyConfiguration)
	}
	return fmt.Errorf("%w: version %d", ErrUnsupportedSchemaVersion, version)
}
