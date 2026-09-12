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
// 目前支持版本 1 与版本 2；其余版本返回 ErrUnsupportedSchemaVersion。
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
