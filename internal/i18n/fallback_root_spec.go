package i18n

import domi18n "github.com/wentf9/xops-cli/core/domain/i18n"

// rootFallback 返回根模块错误、诊断与提示类 MessageID 对应的规范英文兜底模板（纯函数、零包级 var）。
// 每条返回文本须与 locales/en/*.yaml 中的对应词条保持 100% 逐字一致，由 catalog_test.go 强制锁死。
func rootFallback(id domi18n.MessageID) string {
	if text := fallbackCatalog(id); text != "" {
		return text
	}
	if text := fallbackStdAndConc(id); text != "" {
		return text
	}
	if text := fallbackCLI(id); text != "" {
		return text
	}
	if text := fallbackTUI(id); text != "" {
		return text
	}
	if text := fallbackSFTPAndDaemons(id); text != "" {
		return text
	}
	return fallbackInteract(id)
}

// fallbackForID 先查根模块规范英文兜底表，未命中再回退核心规范英文兜底表。
func fallbackForID(id domi18n.MessageID) string {
	if text := rootFallback(id); text != "" {
		return text
	}
	return domi18n.CanonicalFallback(id)
}

func fallbackCatalog(id domi18n.MessageID) string {
	switch id {
	case KeyCatalogCorrupt:
		return "i18n: catalog data is corrupt"
	case KeyCatalogLoadFailed:
		return "i18n: failed to load catalog file {file}"
	case KeyCatalogMissingLocale:
		return "i18n: missing locale catalog {locale}"
	case KeyCatalogInvalidYAML:
		return "i18n: invalid YAML catalog in {file}"
	case KeyCatalogInvalidKey:
		return "i18n: invalid message key {key} in {file}"
	case KeyCatalogDuplicateKey:
		return "i18n: duplicate message key {key} in locale {locale}"
	case KeyCatalogInvalidEntry:
		return "i18n: invalid catalog entry for key {key}"
	case KeyCatalogInvalidEntryNode:
		return "i18n: catalog entry must be a non-empty string or plural mapping"
	case KeyCatalogEmptyEntry:
		return "i18n: catalog entry template must not be empty"
	case KeyCatalogUnknownField:
		return "i18n: unknown field {field} in entry"
	case KeyCatalogDuplicateField:
		return "i18n: duplicate field {field} in entry"
	case KeyCatalogNonScalarField:
		return "i18n: entry field {field} must be a non-empty string"
	case KeyCatalogMissingOther:
		return "i18n: plural entry missing required other field"
	case KeyCatalogInvalidTemplate:
		return "i18n: invalid template syntax for key {key}"
	case KeyCatalogPluralPlaceholderMismatch:
		return "i18n: plural entry one and other placeholders do not match"
	case KeyCatalogPlaceholderMismatch:
		return "i18n: placeholder mismatch for key {key}"
	case KeyCatalogMissingKey:
		return "i18n: missing message key {key} in locale {locale}"
	default:
		return ""
	}
}

func fallbackStdAndConc(id domi18n.MessageID) string {
	switch id {
	case KeyStdContextCanceled:
		return "context canceled"
	case KeyStdDeadlineExceeded:
		return "context deadline exceeded"
	case KeyConcNurseryNotInitialized:
		return "conc: nursery is not initialized"
	case KeyConcNurseryClosed:
		return "conc: nursery is closed or waiting and rejects new tasks"
	case KeyConcNilTask:
		return "conc: task callback must not be nil"
	case KeyConcTaskPanicked:
		return "conc: supervised goroutine panicked"
	case KeyConcMutexNotInitialized:
		return "conc: CtxMutex is not initialized"
	case KeyConcNilContext:
		return "conc: context must not be nil"
	case KeyConcPanic:
		return "conc: supervised goroutine panicked: {value}"
	default:
		return ""
	}
}
