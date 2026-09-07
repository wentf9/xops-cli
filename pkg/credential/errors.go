package credential

import "errors"

var (
	// ErrCredentialNotFound 表示凭据项在指定的凭据存储中未找到。
	ErrCredentialNotFound = errors.New("credential not found")

	// ErrCredentialStoreLocked 表示目标凭据存储处于锁定状态，需要用户解锁。
	ErrCredentialStoreLocked = errors.New("credential store is locked")

	// ErrCredentialStoreUnavailable 表示凭据存储当前不可达或未就绪。
	ErrCredentialStoreUnavailable = errors.New("credential store is unavailable")

	// ErrCredentialAccessDenied 表示当前用户或进程无权访问该凭据存储。
	ErrCredentialAccessDenied = errors.New("credential access denied")

	// ErrCredentialStoreReadOnly 表示该凭据源为只读，不支持写入或删除操作。
	ErrCredentialStoreReadOnly = errors.New("credential store is read-only")

	// ErrInteractionRequired 表示非交互场景下需要用户交互输入凭据，执行失败关闭。
	ErrInteractionRequired = errors.New("interaction required")

	// ErrConfigConflict 表示并发写入或版本 CAS 校验发生冲突。
	ErrConfigConflict = errors.New("configuration conflict")

	// ErrInvalidRef 表示凭据引用格式非法或 storeID/itemID 不完整。
	ErrInvalidRef = errors.New("invalid credential reference")

	// ErrStoreNotFound 表示指定的 StoreID 未在 Registry 中注册。
	ErrStoreNotFound = errors.New("credential store not found")

	// ErrStoreAlreadyRegistered 表示指定的 StoreID 已存在注册项。
	ErrStoreAlreadyRegistered = errors.New("credential store already registered")

	// ErrJournalCorrupted 表示凭据恢复日志格式损坏或校验失败。
	ErrJournalCorrupted = errors.New("credential recovery journal corrupted")

	// ErrSchemaValidation 表示配置 Schema v2 校验失败。
	ErrSchemaValidation = errors.New("schema validation failed")

	// ErrUnsupportedSchemaVersion 表示不支持的配置文件 schema_version。
	ErrUnsupportedSchemaVersion = errors.New("unsupported schema version")
)
