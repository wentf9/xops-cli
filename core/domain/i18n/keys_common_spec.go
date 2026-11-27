package i18n

import "github.com/wentf9/xops-cli/core/domain/i18n/internal/corecatalog"

// 本文件声明核心通用及 i18n 基础设施强类型 MessageID 常量、不可变哨兵错误，
// 并将规范英文兜底查询与全量键集合委托至无环内部子包 core/domain/i18n/internal/corecatalog。
const (
	// i18n 核心基础设施与语言/参数/模板错误标识（既有 M1 契约，禁止变更键名与英文兜底）。
	KeyLocaleInvalid         MessageID = "i18n.locale.invalid"           // 语言标签无效（哨兵）
	KeyLocaleInvalidValue    MessageID = "i18n.locale.invalid_value"     // 语言标签取值无效
	KeyParamInvalid          MessageID = "i18n.param.invalid"            // 消息参数无效（哨兵）
	KeyParamInvalidKey       MessageID = "i18n.param.invalid_key"        // 参数键名非法
	KeyParamInvalidKind      MessageID = "i18n.param.invalid_kind"       // 参数变体种类非法
	KeyParamInvalidValue     MessageID = "i18n.param.invalid_value"      // 参数取值非法
	KeyParamDepthExceeded    MessageID = "i18n.param.depth_exceeded"     // 嵌套消息参数深度超限
	KeyMessageInvalid        MessageID = "i18n.message.invalid"          // 结构化消息无效（哨兵）
	KeyMessageTooManyParams  MessageID = "i18n.message.too_many_params"  // 单条消息参数数超限
	KeyMessageDuplicateParam MessageID = "i18n.message.duplicate_param"  // 单条消息参数键重复
	KeyTemplateInvalid       MessageID = "i18n.template.invalid"         // 消息模板无效（哨兵）
	KeyTemplateUnclosed      MessageID = "i18n.template.unclosed"        // 模板占位符未闭合
	KeyTemplateUnescaped     MessageID = "i18n.template.unescaped_brace" // 模板右花括号未转义
	KeyTemplateBadKey        MessageID = "i18n.template.invalid_key"     // 模板占位符键名非法
	KeyNilReceiver           MessageID = "i18n.nil_receiver"             // 反序列化接收者为 nil（哨兵）

	// 通用基础错误标识（既有 M1 契约，禁止变更键名与英文兜底）。
	KeyCommonNilContext      MessageID = "common.nil_context"       // 上下文为 nil
	KeyCommonNotInitialized  MessageID = "common.not_initialized"   // 组件未初始化
	KeyCommonInvalidArgument MessageID = "common.invalid_argument"  // 调用参数非法
	KeyCommonLimitExceeded   MessageID = "common.limit_exceeded"    // 超出安全上限
	KeyCommonNilCallback     MessageID = "common.nil_callback"      // 回调函数为 nil
	KeyCommonNotFound        MessageID = "common.not_found"         // 目标资源不存在
	KeyCommonAlreadyExists   MessageID = "common.already_exists"    // 目标资源已存在
	KeyCommonCanceled        MessageID = "common.canceled"          // 操作已取消
	KeyCommonTimeout         MessageID = "common.timeout"           // 操作超时
	KeyCommonPermissionDeny  MessageID = "common.permission_denied" // 权限不足或策略拒绝
	KeyCommonInternalError   MessageID = "common.internal_error"    // 非预期内部错误
	KeyCommonErrorJoin       MessageID = "common.error_join"        // 多段结构化错误链连接模板

	// M3 跨层复用参数化校验、编解码与操作诊断模板。
	KeyCommonFieldRequired      MessageID = "common.field_required"       // 必填字段缺失
	KeyCommonFieldInvalid       MessageID = "common.field_invalid"        // 字段取值非法（含值）
	KeyCommonFieldValueInvalid  MessageID = "common.field_value_invalid"  // 字段状态或结构无效
	KeyCommonFieldEmpty         MessageID = "common.field_empty"          // 字段内容为空
	KeyCommonFieldPositive      MessageID = "common.field_positive"       // 数值或时长须为正
	KeyCommonFieldNegative      MessageID = "common.field_negative"       // 数值或时长不可为负
	KeyCommonFieldRange         MessageID = "common.field_range"          // 数值越界（闭区间）
	KeyCommonFieldMaxExceeded   MessageID = "common.field_max_exceeded"   // 数值超过上限
	KeyCommonFieldNil           MessageID = "common.field_nil"            // 必填依赖或句柄为 nil
	KeyCommonIndexInvalid       MessageID = "common.index_invalid"        // 切片元素无效
	KeyCommonIndexValueInvalid  MessageID = "common.index_value_invalid"  // 切片元素取值无效
	KeyCommonDuplicateItem      MessageID = "common.duplicate_item"       // 唯一项重复
	KeyCommonMismatch           MessageID = "common.mismatch"             // 期望与实际值失配
	KeyCommonStateForbidden     MessageID = "common.state_forbidden"      // 当前状态禁止操作
	KeyCommonStateInputRejected MessageID = "common.state_input_rejected" // 状态拒绝该输入
	KeyCommonUnknownValue       MessageID = "common.unknown_value"        // 未知枚举或类别取值
	KeyCommonValueInvalid       MessageID = "common.value_invalid"        // 通用非法值诊断
	KeyCommonOpFailed           MessageID = "common.op_failed"            // 通用操作执行失败
	KeyCommonOpTargetFailed     MessageID = "common.op_target_failed"     // 针对目标的操作失败
	KeyCommonPathForbidden      MessageID = "common.path_forbidden"       // 路径被安全规则拒绝
	KeyCommonNotSupported       MessageID = "common.not_supported"        // 不支持的功能或变体
	KeyCommonMissingDep         MessageID = "common.missing_dep"          // 必需端口或服务未装配
	KeyCommonComponentClosed    MessageID = "common.component_closed"     // 组件未初始化或已关闭
	KeyCommonCountLimit         MessageID = "common.count_limit"          // 条目数量超限
	KeyCommonSizeLimit          MessageID = "common.size_limit"           // 字节大小超限
	KeyCommonJSONNullForbidden  MessageID = "common.json_null_forbidden"  // 拒绝 JSON null
	KeyCommonJSONTrailingData   MessageID = "common.json_trailing_data"   // JSON 存在尾随多余内容
	KeyCommonJSONMissingField   MessageID = "common.json_missing_field"   // 缺少必需编码字段
	KeyCommonJSONVariantInvalid MessageID = "common.json_variant_invalid" // 变体字段组合非法
	KeyCommonMutuallyExclusive  MessageID = "common.mutually_exclusive"   // 两字段或选项互斥
	KeyCommonOneOfRequired      MessageID = "common.one_of_required"      // 多选一必填约束违例
	KeyCommonInvalidTextChars   MessageID = "common.invalid_text_chars"   // 文本超长或含非法控制字符
	KeyCommonInvalidUTF8        MessageID = "common.invalid_utf8"         // 输入含非法 UTF-8 字节
	KeyCommonBase64DecodeFailed MessageID = "common.base64_decode_failed" // Base64 解码失败
	KeyCommonZeroEntropy        MessageID = "common.zero_entropy"         // 熵源返回全零字节
	KeyCommonPermInvalid        MessageID = "common.perm_invalid"         // POSIX 文件权限位非法
	KeyCommonDetail             MessageID = "common.detail"               // 受限净化原始明细
)

// 本包导出的不可变哨兵错误集合，均经 Sentinel 构造以支持 errors.Is 语义匹配与边界延迟本地化。
var (
	ErrInvalidLocale   = Sentinel(KeyLocaleInvalid)   // 语言标签为空、格式非法或不受支持
	ErrInvalidParam    = Sentinel(KeyParamInvalid)    // 结构化消息参数键名、种类或取值非法
	ErrInvalidMessage  = Sentinel(KeyMessageInvalid)  // 结构化消息标识、参数集或嵌套深度非法
	ErrInvalidTemplate = Sentinel(KeyTemplateInvalid) // 消息模板语法或占位符键名非法
	ErrNilReceiver     = Sentinel(KeyNilReceiver)     // 反序列化目标指针接收者为 nil
)

// CanonicalFallback 返回 core/domain/i18n 注册消息标识对应的规范英文兜底模板（纯函数、零包级 var）。
// 未注册标识及 MessageIDInvalid 一律返回空串；每条规范英文模板须与根模块 en/*.yaml 保持 100% 一致。
func CanonicalFallback(id MessageID) string {
	return corecatalog.Lookup(string(id))
}

// CoreKeys 返回 core/domain/i18n 注册的全部有效 MessageID 列表（严格有序、去重且排除 MessageIDInvalid），
// 供根模块 internal/i18n/catalog_test.go 执行双语词库 100% 双射与兜底一致性校验。
func CoreKeys() []MessageID {
	raw := corecatalog.AllKeys()
	out := make([]MessageID, len(raw))
	for i, k := range raw {
		out[i] = MessageID(k)
	}
	return out
}
