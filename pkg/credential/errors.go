package credential

import (
	"errors"
)

var (
	// ErrCredentialStoreReadOnly 表示该凭据源为只读，不支持写入或删除操作。
	ErrCredentialStoreReadOnly = errors.New("credential store is read-only")

	// ErrInteractionRequired 表示非交互场景下需要用户交互输入凭据，执行失败关闭。
	ErrInteractionRequired = errors.New("interaction required")

	// ErrStoreAlreadyRegistered 表示指定的 StoreID 已存在注册项。
	ErrStoreAlreadyRegistered = errors.New("credential store already registered")

	// ErrJournalCorrupted 表示凭据恢复日志格式损坏或校验失败。
	ErrJournalCorrupted = errors.New("credential recovery journal corrupted")

	// ErrSchemaValidation 表示配置 Schema v2 校验失败。
	ErrSchemaValidation = errors.New("schema validation failed")

	// ErrUnsupportedSchemaVersion 表示不支持的配置文件 schema_version。
	ErrUnsupportedSchemaVersion = errors.New("unsupported schema version")
)
