package i18n

// CanonicalFallback 返回 core/domain/i18n 注册消息标识对应的规范英文兜底模板（纯函数、零包级 var）。
// 未注册标识及 MessageIDInvalid 一律返回空串；每条规范英文模板须与根模块 en/*.yaml 保持 100% 一致。
func CanonicalFallback(id MessageID) string {
	if text := fallbackI18n(id); text != "" {
		return text
	}
	if text := fallbackCommon(id); text != "" {
		return text
	}
	return fallbackInteract(id)
}

func fallbackI18n(id MessageID) string {
	switch id {
	case KeyLocaleInvalid:
		return "i18n: invalid locale"
	case KeyLocaleInvalidValue:
		return "i18n: invalid locale {value}"
	case KeyParamInvalid:
		return "i18n: invalid message parameter"
	case KeyParamInvalidKey:
		return "i18n: invalid parameter key {key}"
	case KeyParamInvalidKind:
		return "i18n: invalid parameter kind {kind}"
	case KeyParamInvalidValue:
		return "i18n: invalid parameter value for {key}"
	case KeyParamDepthExceeded:
		return "i18n: nested message depth exceeds maximum {max}"
	case KeyMessageInvalid:
		return "i18n: invalid message"
	case KeyMessageTooManyParams:
		return "i18n: message parameter count exceeds maximum {max}"
	case KeyMessageDuplicateParam:
		return "i18n: duplicate parameter key {key}"
	case KeyTemplateInvalid:
		return "i18n: invalid message template"
	case KeyTemplateUnclosed:
		return "i18n: unclosed placeholder in message template"
	case KeyTemplateUnescaped:
		return "i18n: unescaped closing brace in message template"
	case KeyTemplateBadKey:
		return "i18n: invalid placeholder key {key}"
	case KeyNilReceiver:
		return "i18n: unmarshal target receiver must not be nil"
	default:
		return ""
	}
}

func fallbackCommon(id MessageID) string {
	switch id {
	case KeyCommonNilContext:
		return "context must not be nil"
	case KeyCommonNotInitialized:
		return "component is not initialized"
	case KeyCommonInvalidArgument:
		return "invalid argument"
	case KeyCommonLimitExceeded:
		return "limit exceeded"
	case KeyCommonNilCallback:
		return "callback must not be nil"
	case KeyCommonNotFound:
		return "resource not found"
	case KeyCommonAlreadyExists:
		return "resource already exists"
	case KeyCommonCanceled:
		return "operation canceled"
	case KeyCommonTimeout:
		return "operation timed out"
	case KeyCommonPermissionDeny:
		return "permission denied"
	case KeyCommonInternalError:
		return "internal error"
	case KeyCommonErrorJoin:
		return "{head}: {tail}"
	default:
		return ""
	}
}
