package i18n

// 本文件声明核心通用及 i18n 基础设施使用的强类型 MessageID 常量与不可变哨兵错误。
const (
	// KeyLocaleInvalid 表示语言标签无效（哨兵与通用诊断）。
	KeyLocaleInvalid MessageID = "i18n.locale.invalid"
	// KeyLocaleInvalidValue 表示带非法取值参数的语言标签解析失败。
	KeyLocaleInvalidValue MessageID = "i18n.locale.invalid_value"
	// KeyParamInvalid 表示结构化消息参数无效（哨兵）。
	KeyParamInvalid MessageID = "i18n.param.invalid"
	// KeyParamInvalidKey 表示参数键名非法。
	KeyParamInvalidKey MessageID = "i18n.param.invalid_key"
	// KeyParamInvalidKind 表示参数变体种类不受支持。
	KeyParamInvalidKind MessageID = "i18n.param.invalid_kind"
	// KeyParamInvalidValue 表示参数取值非法或与种类不匹配。
	KeyParamInvalidValue MessageID = "i18n.param.invalid_value"
	// KeyParamDepthExceeded 表示嵌套消息参数深度超出上限。
	KeyParamDepthExceeded MessageID = "i18n.param.depth_exceeded"
	// KeyMessageInvalid 表示结构化消息无效（哨兵）。
	KeyMessageInvalid MessageID = "i18n.message.invalid"
	// KeyMessageTooManyParams 表示单条消息参数个数超出上限。
	KeyMessageTooManyParams MessageID = "i18n.message.too_many_params"
	// KeyMessageDuplicateParam 表示单条消息包含重复参数键名。
	KeyMessageDuplicateParam MessageID = "i18n.message.duplicate_param"
	// KeyTemplateInvalid 表示消息模板无效（哨兵）。
	KeyTemplateInvalid MessageID = "i18n.template.invalid"
	// KeyTemplateUnclosed 表示消息模板存在未闭合的占位符花括号。
	KeyTemplateUnclosed MessageID = "i18n.template.unclosed"
	// KeyTemplateUnescaped 表示消息模板存在未转义的右花括号。
	KeyTemplateUnescaped MessageID = "i18n.template.unescaped_brace"
	// KeyTemplateBadKey 表示消息模板占位符键名非法。
	KeyTemplateBadKey MessageID = "i18n.template.invalid_key"
	// KeyNilReceiver 表示在 nil 指针接收者上调用反序列化方法。
	KeyNilReceiver MessageID = "i18n.nil_receiver"

	// KeyCommonNilContext 表示传入的 context.Context 为 nil。
	KeyCommonNilContext MessageID = "common.nil_context"
	// KeyCommonNotInitialized 表示对象或子系统尚未完成初始化。
	KeyCommonNotInitialized MessageID = "common.not_initialized"
	// KeyCommonInvalidArgument 表示调用参数非法或违反前置不变量。
	KeyCommonInvalidArgument MessageID = "common.invalid_argument"
	// KeyCommonLimitExceeded 表示数量、长度或配额超出安全上限。
	KeyCommonLimitExceeded MessageID = "common.limit_exceeded"
	// KeyCommonNilCallback 表示传入的必需回调函数为 nil。
	KeyCommonNilCallback MessageID = "common.nil_callback"
	// KeyCommonNotFound 表示请求的目标对象不存在。
	KeyCommonNotFound MessageID = "common.not_found"
	// KeyCommonAlreadyExists 表示目标对象或唯一标识已存在。
	KeyCommonAlreadyExists MessageID = "common.already_exists"
	// KeyCommonCanceled 表示操作已被调用方或上下文取消。
	KeyCommonCanceled MessageID = "common.canceled"
	// KeyCommonTimeout 表示操作在截止时间前未完成。
	KeyCommonTimeout MessageID = "common.timeout"
	// KeyCommonPermissionDeny 表示权限不足或被安全策略拒绝。
	KeyCommonPermissionDeny MessageID = "common.permission_denied"
	// KeyCommonInternalError 表示非预期内部状态错误。
	KeyCommonInternalError MessageID = "common.internal_error"
	// KeyCommonErrorJoin 表示多段结构化错误链连接模板（"{head}: {tail}"）。
	KeyCommonErrorJoin MessageID = "common.error_join"
)

// 本包导出的不可变哨兵错误集合，均经 Sentinel 构造以支持 errors.Is 语义匹配与边界延迟本地化。
var (
	// ErrInvalidLocale 表示语言标签为空、格式非法或不受支持。
	ErrInvalidLocale = Sentinel(KeyLocaleInvalid)
	// ErrInvalidParam 表示结构化消息参数键名、种类或取值非法。
	ErrInvalidParam = Sentinel(KeyParamInvalid)
	// ErrInvalidMessage 表示结构化消息标识、参数集或嵌套深度非法。
	ErrInvalidMessage = Sentinel(KeyMessageInvalid)
	// ErrInvalidTemplate 表示消息模板语法或占位符键名非法。
	ErrInvalidTemplate = Sentinel(KeyTemplateInvalid)
	// ErrNilReceiver 表示反序列化目标指针接收者为 nil。
	ErrNilReceiver = Sentinel(KeyNilReceiver)
)

// CoreKeys 返回 core/domain/i18n 注册的全部有效 MessageID 列表（严格排除 MessageIDInvalid），
// 供根模块 internal/i18n/catalog_test.go 执行双语词库 100% 双射与兜底一致性校验。
func CoreKeys() []MessageID {
	return append([]MessageID{
		KeyLocaleInvalid,
		KeyLocaleInvalidValue,
		KeyParamInvalid,
		KeyParamInvalidKey,
		KeyParamInvalidKind,
		KeyParamInvalidValue,
		KeyParamDepthExceeded,
		KeyMessageInvalid,
		KeyMessageTooManyParams,
		KeyMessageDuplicateParam,
		KeyTemplateInvalid,
		KeyTemplateUnclosed,
		KeyTemplateUnescaped,
		KeyTemplateBadKey,
		KeyNilReceiver,
		KeyCommonNilContext,
		KeyCommonNotInitialized,
		KeyCommonInvalidArgument,
		KeyCommonLimitExceeded,
		KeyCommonNilCallback,
		KeyCommonNotFound,
		KeyCommonAlreadyExists,
		KeyCommonCanceled,
		KeyCommonTimeout,
		KeyCommonPermissionDeny,
		KeyCommonInternalError,
		KeyCommonErrorJoin,
	}, interactKeys()...)
}
