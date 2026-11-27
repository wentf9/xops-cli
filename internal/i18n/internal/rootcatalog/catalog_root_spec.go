package rootcatalog

// 本文件收录词库加载器、标准库 context 与 core/conc 映射键的规范英文兜底模板与键清单。
func lookupRoot(id string) string {
	switch id {
	case "i18n.catalog.corrupt":
		return "i18n: catalog data is corrupt"
	case "i18n.catalog.load_failed":
		return "i18n: failed to load catalog file {file}"
	case "i18n.catalog.missing_locale":
		return "i18n: missing locale catalog {locale}"
	case "i18n.catalog.invalid_yaml":
		return "i18n: invalid YAML catalog in {file}"
	case "i18n.catalog.invalid_key":
		return "i18n: invalid message key {key} in {file}"
	case "i18n.catalog.duplicate_key":
		return "i18n: duplicate message key {key} in locale {locale}"
	case "i18n.catalog.invalid_entry":
		return "i18n: invalid catalog entry for key {key}"
	case "i18n.catalog.invalid_entry_node":
		return "i18n: catalog entry must be a non-empty string or plural mapping"
	case "i18n.catalog.empty_entry":
		return "i18n: catalog entry template must not be empty"
	case "i18n.catalog.unknown_field":
		return "i18n: unknown field {field} in entry"
	case "i18n.catalog.duplicate_field":
		return "i18n: duplicate field {field} in entry"
	case "i18n.catalog.non_scalar_field":
		return "i18n: entry field {field} must be a non-empty string"
	case "i18n.catalog.missing_other":
		return "i18n: plural entry missing required other field"
	case "i18n.catalog.invalid_template":
		return "i18n: invalid template syntax for key {key}"
	case "i18n.catalog.plural_placeholder_mismatch":
		return "i18n: plural entry one and other placeholders do not match"
	case "i18n.catalog.placeholder_mismatch":
		return "i18n: placeholder mismatch for key {key}"
	case "i18n.catalog.missing_key":
		return "i18n: missing message key {key} in locale {locale}"
	case "std.context.canceled":
		return "context canceled"
	case "std.context.deadline_exceeded":
		return "context deadline exceeded"
	case "conc.nursery.not_initialized":
		return "conc: nursery is not initialized"
	case "conc.nursery.closed":
		return "conc: nursery is closed or waiting and rejects new tasks"
	case "conc.nil_task":
		return "conc: task callback must not be nil"
	case "conc.task_panicked":
		return "conc: supervised goroutine panicked"
	case "conc.mutex.not_initialized":
		return "conc: CtxMutex is not initialized"
	case "conc.nil_context":
		return "conc: context must not be nil"
	case "conc.panic_value":
		return "conc: supervised goroutine panicked: {value}"
	default:
		return ""
	}
}

func errorKeysRoot() []string {
	return []string{
		"i18n.catalog.corrupt",
		"i18n.catalog.load_failed",
		"i18n.catalog.missing_locale",
		"i18n.catalog.invalid_yaml",
		"i18n.catalog.invalid_key",
		"i18n.catalog.duplicate_key",
		"i18n.catalog.invalid_entry",
		"i18n.catalog.invalid_entry_node",
		"i18n.catalog.empty_entry",
		"i18n.catalog.unknown_field",
		"i18n.catalog.duplicate_field",
		"i18n.catalog.non_scalar_field",
		"i18n.catalog.missing_other",
		"i18n.catalog.invalid_template",
		"i18n.catalog.plural_placeholder_mismatch",
		"i18n.catalog.placeholder_mismatch",
		"i18n.catalog.missing_key",
		"std.context.canceled",
		"std.context.deadline_exceeded",
		"conc.nursery.not_initialized",
		"conc.nursery.closed",
		"conc.nil_task",
		"conc.task_panicked",
		"conc.mutex.not_initialized",
		"conc.nil_context",
		"conc.panic_value",
	}
}
