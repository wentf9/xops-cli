package i18n

// 本文件声明 Wave 3B（core/ports、core/events、core/osfs 与 foundation/{actor,trace}）全部哨兵与上下文强类型 MessageID 常量。
const (
	// core/ports 哨兵、自定义结构与上下文错误标识（41 哨兵 + 5 上下文）。
	KeyPortsNilContext           MessageID = "ports.nil_context"                 // context 为 nil
	KeyPortsNilCallback          MessageID = "ports.nil_callback"                // 作用域回调为 nil
	KeyPortsNilReceiver          MessageID = "ports.nil_receiver"                // 反序列化接收者为 nil
	KeyPortsInvalidArgument      MessageID = "ports.invalid_argument"            // 端口调用参数无效
	KeyPortsUnsupported          MessageID = "ports.unsupported"                 // 适配器不支持该操作
	KeyPortsClosed               MessageID = "ports.closed"                      // 端口或会话已关闭
	KeyPortsNotFound             MessageID = "ports.not_found"                   // 目标资源不存在
	KeyPortsAlreadyExists        MessageID = "ports.already_exists"              // 目标资源已存在
	KeyPortsPermissionDenied     MessageID = "ports.permission_denied"           // 权限不足或策略拒绝
	KeyPortsLimitExceeded        MessageID = "ports.limit_exceeded"              // 超出安全上限
	KeyPortsRevisionConflict     MessageID = "ports.revision_conflict"           // 配置版本 CAS 冲突
	KeyPortsCorruptData          MessageID = "ports.corrupt_data"                // 持久化数据损坏
	KeyPortsInvalidRevision      MessageID = "ports.invalid_revision"            // 配置版本无效
	KeyPortsInvalidDurability    MessageID = "ports.invalid_durability"          // 持久化提交结果无效
	KeyPortsInvalidLockMode      MessageID = "ports.invalid_lock_mode"           // 文件锁模式无效
	KeyPortsInvalidReadLimits    MessageID = "ports.invalid_read_limits"         // 读取上限无效
	KeyPortsLockBusy             MessageID = "ports.lock_busy"                   // 文件锁被占用
	KeyPortsNotRegularFile       MessageID = "ports.not_regular_file"            // 目标不是常规文件
	KeyPortsSymlinkRejected      MessageID = "ports.symlink_rejected"            // 软链接被策略拒绝
	KeyPortsHandleExpired        MessageID = "ports.handle_expired"              // 作用域借用句柄已失效
	KeyPortsVaultLocked          MessageID = "ports.vault_locked"                // 凭据库处于锁定状态
	KeyPortsSecretNotFound       MessageID = "ports.secret_not_found"            // 凭据条目不存在
	KeyPortsSecretVerifyFailed   MessageID = "ports.secret_verify_failed"        // 凭据回读校验不一致
	KeyPortsHostKeyMismatch      MessageID = "ports.host_key_mismatch"           // 主机密钥指纹失配
	KeyPortsHostKeyUnknown       MessageID = "ports.host_key_unknown"            // 未知主机密钥被策略拒绝
	KeyPortsHostKeyRevoked       MessageID = "ports.host_key_revoked"            // 主机密钥已被吊销
	KeyPortsSignerUnavailable    MessageID = "ports.signer_unavailable"          // 密钥签名器或 Agent 不可用
	KeyPortsDialFailed           MessageID = "ports.dial_failed"                 // 建立远端传输连接失败
	KeyPortsAuthFailed           MessageID = "ports.auth_failed"                 // 远端身份认证失败
	KeyPortsMuxUnavailable       MessageID = "ports.mux_unavailable"             // 多路复用套接字不可用
	KeyPortsRemoteAnchorMismatch MessageID = "ports.remote_anchor_mismatch"      // 远端文件锚点不匹配
	KeyPortsRemoteIsDir          MessageID = "ports.remote_is_dir"               // 远端目标为目录
	KeyPortsAuditWriteFailed     MessageID = "ports.audit_write_failed"          // 审计日志写入失败
	KeyPortsAuditPostWrite       MessageID = "ports.audit_post_write"            // 审计后置终态写入失败
	KeyPortsAuditHalted          MessageID = "ports.audit_halted"                // 审计门控已触发 Halted 熔断
	KeyPortsInvalidAuditEntry    MessageID = "ports.invalid_audit_entry"         // 审计记录无效
	KeyPortsInvalidProcInstID    MessageID = "ports.invalid_process_instance_id" // 进程实例标识无效
	KeyPortsInteractionUnavail   MessageID = "ports.interaction_unavailable"     // 当前环境不支持交互
	KeyPortsInteractionCanceled  MessageID = "ports.interaction_canceled"        // 用户取消或拒绝交互
	KeyPortsEntropyShortRead     MessageID = "ports.entropy_short_read"          // 熵源读取字节数不足
	KeyPortsInvalidTTYSize       MessageID = "ports.invalid_tty_size"            // 终端窗口尺寸无效
	KeyPortsAuditPostWriteOp     MessageID = "ports.audit_post_write_op"         // 审计后置终态写入失败（含操作 ID）
	KeyPortsPromptMsgInvalid     MessageID = "ports.prompt_msg_invalid"          // 结构化交互提示消息无效或越界
	KeyPortsModTimeOutOfRange    MessageID = "ports.mod_time_out_of_range"       // 修改时间超出 RFC 3339 合法年份
	KeyPortsDurabilitySpec       MessageID = "ports.durability_spec"             // 持久化状态字段组合非法
	KeyPortsTUNSpecConflict      MessageID = "ports.tun_spec_conflict"           // ForwardTUN 端点规格冲突

	// core/events 哨兵与上下文错误标识（30 哨兵 + 4 上下文）。
	KeyEventsNilContext          MessageID = "events.nil_context"                      // context 为 nil
	KeyEventsNilReceiver         MessageID = "events.nil_receiver"                     // 反序列化接收者为 nil
	KeyEventsNilWriter           MessageID = "events.nil_writer"                       // 编码输出 writer 为 nil
	KeyEventsInvalidEvent        MessageID = "events.invalid_event"                    // 事件实例或变体无效
	KeyEventsInvalidEventMeta    MessageID = "events.invalid_event_meta"               // EventMeta 无效
	KeyEventsInvalidEventKind    MessageID = "events.invalid_event_kind"               // EventKind 无效
	KeyEventsInvalidEventClass   MessageID = "events.invalid_event_class"              // EventClass 无效
	KeyEventsInvalidBackpressure MessageID = "events.invalid_backpressure"             // 背压策略无效
	KeyEventsInvalidSeverity     MessageID = "events.invalid_severity"                 // 严重等级无效
	KeyEventsInvalidOutputStream MessageID = "events.invalid_output_stream"            // 输出流种类无效
	KeyEventsInvalidAuditStage   MessageID = "events.invalid_audit_stage"              // 审计阶段无效
	KeyEventsInvalidPoolAction   MessageID = "events.invalid_pool_action"              // 连接池事件动作无效
	KeyEventsInvalidDiagScope    MessageID = "events.invalid_diagnostic_scope"         // 诊断作用域无效
	KeyEventsInvalidFSMMachine   MessageID = "events.invalid_fsm_machine"              // 状态机类别无效
	KeyEventsUnsupportedClass    MessageID = "events.unsupported_event_class"          // 通道不支持该事件类别
	KeyEventsOperationMismatch   MessageID = "events.operation_mismatch"               // 事件与操作流绑定不一致
	KeyEventsInvalidStreamConfig MessageID = "events.invalid_stream_config"            // 操作流配置无效
	KeyEventsStreamNotInit       MessageID = "events.stream_not_initialized"           // 操作流未初始化
	KeyEventsStreamClosed        MessageID = "events.stream_closed"                    // 操作流已关闭
	KeyEventsInvalidFoldFunc     MessageID = "events.invalid_fold_func"                // 归约函数为 nil
	KeyEventsInvalidAuditConfig  MessageID = "events.invalid_audit_config"             // 审计分发器配置无效
	KeyEventsNilAuditWriter      MessageID = "events.nil_audit_writer"                 // AuditWriter 为 nil
	KeyEventsAuditDispNotInit    MessageID = "events.audit_dispatcher_not_initialized" // 审计分发器未初始化
	KeyEventsAuditHalted         MessageID = "events.audit_halted"                     // 审计分发器已熔断
	KeyEventsAuditDispatchFailed MessageID = "events.audit_dispatch_failed"            // 同步审计分发失败
	KeyEventsInvalidBusConfig    MessageID = "events.invalid_bus_config"               // 系统总线配置无效
	KeyEventsBusNotInit          MessageID = "events.bus_not_initialized"              // 系统总线未初始化
	KeyEventsBusClosed           MessageID = "events.bus_closed"                       // 系统总线已关闭
	KeyEventsBusSubscriberLimit  MessageID = "events.bus_subscriber_limit"             // 系统总线订阅数达上限
	KeyEventsSubNotInit          MessageID = "events.subscription_not_initialized"     // 订阅句柄未初始化
	KeyEventsClassMismatch       MessageID = "events.class_mismatch"                   // 事件通道类别不匹配
	KeyEventsAuditConflict       MessageID = "events.audit_conflict"                   // 审计阶段与安全决策矛盾
	KeyEventsOutcomeConflict     MessageID = "events.outcome_conflict"                 // 事件状态与执行结果矛盾
	KeyEventsJSONObjectRequired  MessageID = "events.json_object_required"             // 事件 JSON 必须为对象

	// core/osfs 哨兵与上下文错误标识（8 哨兵 + 12 上下文）。
	KeyOSFSSlotOccupied         MessageID = "osfs.slot_occupied"          // 控制套接字槽位已占用
	KeyOSFSNotSocket            MessageID = "osfs.not_socket"             // 目标路径不是本地 Unix 套接字
	KeyOSFSInvalidControlPath   MessageID = "osfs.invalid_control_path"   // 控制套接字路径非法
	KeyOSFSControlPathTooLong   MessageID = "osfs.control_path_too_long"  // 控制套接字路径超 sun_path 上限
	KeyOSFSUnauthorizedPeer     MessageID = "osfs.unauthorized_peer"      // 本地对端身份校验失败
	KeyOSFSUnsupportedPeerCred  MessageID = "osfs.unsupported_peer_cred"  // 平台不支持查询本地对端凭据
	KeyOSFSInsecurePermissions  MessageID = "osfs.insecure_permissions"   // 权限或 DACL 不满足安全不变量
	KeyOSFSSameFileMismatch     MessageID = "osfs.same_file_mismatch"     // 句柄与路径 SameFile 锚定失配
	KeyOSFSNotRegularFile       MessageID = "osfs.not_regular_file"       // 目标路径非常规文件
	KeyOSFSNotDirectory         MessageID = "osfs.not_directory"          // 目标路径非目录
	KeyOSFSSymlinkDetected      MessageID = "osfs.symlink_detected"       // 检测到符号链接或重解析点
	KeyOSFSNotUnixSocket        MessageID = "osfs.not_unix_socket"        // 路径非 AF_UNIX 套接字
	KeyOSFSPeerUIDMismatch      MessageID = "osfs.peer_uid_mismatch"      // 对端 UID 与当前 EUID 失配
	KeyOSFSPeerSIDMismatch      MessageID = "osfs.peer_sid_mismatch"      // 对端进程用户 SID 不受信任
	KeyOSFSNamedPipeInvalid     MessageID = "osfs.named_pipe_invalid"     // Windows 命名管道路径非法
	KeyOSFSDACLCheckFailed      MessageID = "osfs.dacl_check_failed"      // Owner-Only DACL 校验未通过
	KeyOSFSPathPlatformMismatch MessageID = "osfs.path_platform_mismatch" // 路径格式与当前平台不兼容
	KeyOSFSLockTargetReplaced   MessageID = "osfs.lock_target_replaced"   // 加锁目标被并发替换
	KeyOSFSAppendNewline        MessageID = "osfs.append_newline"         // AppendLine 禁含内嵌换行符
	KeyOSFSStaleProbeFailed     MessageID = "osfs.stale_probe_failed"     // 无法确认过期套接字状态

	// core/internal/foundation/{actor,trace} 哨兵与上下文错误标识（8 哨兵 + 1 上下文）。
	KeyActorNotInitialized    MessageID = "actor.not_initialized"     // DualActor 未初始化
	KeyActorAlreadyStarted    MessageID = "actor.already_started"     // DualActor 已启动禁重复运行
	KeyActorStopped           MessageID = "actor.stopped"             // DualActor 已停止
	KeyActorInvalidConfig     MessageID = "actor.invalid_config"      // DualActor 配置无效
	KeyActorNilContext        MessageID = "actor.nil_context"         // context 为 nil
	KeyTraceInvalidLeaseScope MessageID = "trace.invalid_lease_scope" // LeaseScope 无效
	KeyTraceNilContext        MessageID = "trace.nil_context"         // context 为 nil
	KeyTraceReentrantLease    MessageID = "trace.reentrant_lease"     // 禁止重入申请活跃租约
	KeyTraceReentrantDetail   MessageID = "trace.reentrant_detail"    // 活跃租约作用域重入明细
)
