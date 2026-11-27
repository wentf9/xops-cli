package i18n

// 本文件声明 Wave 3A（core/domain/** 11 个领域子包）全部哨兵与上下文强类型 MessageID 常量。
const (
	// core/domain/algebraic 哨兵错误标识（5 项）。
	KeyAlgebraicEmptySlice       MessageID = "algebraic.empty_slice"       // NonEmpty 切片为空
	KeyAlgebraicInvalidDuration  MessageID = "algebraic.invalid_duration"  // Duration 文本格式非法
	KeyAlgebraicDurationOverflow MessageID = "algebraic.duration_overflow" // Duration 加法溢出
	KeyAlgebraicNilReceiver      MessageID = "algebraic.nil_receiver"      // 反序列化接收者为 nil
	KeyAlgebraicNilCallback      MessageID = "algebraic.nil_callback"      // 回调函数为 nil

	// core/domain/execution 哨兵与上下文错误标识（15 哨兵 + 5 上下文）。
	KeyExecutionInvalidLaunchDialect   MessageID = "execution.invalid_launch_dialect"  // 启动方言无效
	KeyExecutionInvalidInterpreter     MessageID = "execution.invalid_interpreter"     // 解释器无效
	KeyExecutionInvalidLoginMode       MessageID = "execution.invalid_login_mode"      // 登录模式无效
	KeyExecutionInvalidLaunchProfile   MessageID = "execution.invalid_launch_profile"  // 启动配置无效
	KeyExecutionUnsupportedCombination MessageID = "execution.unsupported_combination" // 不支持的执行参数组合
	KeyExecutionNotPOSIXBourne         MessageID = "execution.not_posix_bourne"        // 非 POSIX Bourne 启动配置
	KeyExecutionInvalidPlanKind        MessageID = "execution.invalid_plan_kind"       // 计划类型无效
	KeyExecutionInvalidCommandPlan     MessageID = "execution.invalid_command_plan"    // 命令执行计划无效
	KeyExecutionInvalidEnvVar          MessageID = "execution.invalid_env_var"         // 环境变量键值无效
	KeyExecutionInvalidShellQuote      MessageID = "execution.invalid_shell_quote"     // 文本无法安全引用
	KeyExecutionInvalidPhase           MessageID = "execution.invalid_phase"           // 执行阶段枚举无效
	KeyExecutionInvalidExitStatus      MessageID = "execution.invalid_exit_status"     // 退出状态无效
	KeyExecutionInvalidOutcome         MessageID = "execution.invalid_outcome"         // 执行结果无效
	KeyExecutionNilWriter              MessageID = "execution.nil_writer"              // 编码输出 writer 为 nil
	KeyExecutionNilReceiver            MessageID = "execution.nil_receiver"            // 反序列化接收者为 nil
	KeyExecutionScriptPTYForbidden     MessageID = "execution.script_pty_forbidden"    // 脚本计划禁用 PTY
	KeyExecutionScriptInterpreter      MessageID = "execution.script_interpreter"      // 脚本计划需显式解释器
	KeyExecutionProfileMismatch        MessageID = "execution.profile_mismatch"        // 方言与解释器不兼容
	KeyExecutionLoginUnsupported       MessageID = "execution.login_unsupported"       // 解释器不支持该登录模式
	KeyExecutionQuoteForbiddenChar     MessageID = "execution.quote_forbidden_char"    // 命令文本含禁控或不可转义字符

	// core/domain/fsm 哨兵与上下文错误标识（15 哨兵 + 8 上下文）。
	KeyFSMInvalidState             MessageID = "fsm.invalid_state"              // 状态无效或未初始化
	KeyFSMInvalidInput             MessageID = "fsm.invalid_input"              // 输入无效或未初始化
	KeyFSMIllegalTransition        MessageID = "fsm.illegal_transition"         // 非法状态转换
	KeyFSMInvalidContext           MessageID = "fsm.invalid_context"            // 状态机上下文非法
	KeyFSMInvalidDurability        MessageID = "fsm.invalid_durability"         // 持久化提交状态无效
	KeyFSMInvalidOutcome           MessageID = "fsm.invalid_outcome"            // 副作用结果无效
	KeyFSMInvalidJournal           MessageID = "fsm.invalid_journal"            // 传输日志记录无效
	KeyFSMCorruptJournal           MessageID = "fsm.corrupt_journal"            // 传输日志损坏或乱序
	KeyFSMTransferSizeExceeded     MessageID = "fsm.transfer_size_exceeded"     // 传输大小超限或偏移溢出
	KeyFSMInvalidChunkOffset       MessageID = "fsm.invalid_chunk_offset"       // 分片偏移不连续或长度非法
	KeyFSMInvalidApprovalEnvelope  MessageID = "fsm.invalid_approval_envelope"  // 审批信封与上下文失配
	KeyFSMInvalidEnsureStep        MessageID = "fsm.invalid_ensure_step"        // Ensure 步骤参数非法
	KeyFSMInvalidEnrollLease       MessageID = "fsm.invalid_enroll_lease"       // 首连暂存租约上下文非法
	KeyFSMNilWriter                MessageID = "fsm.nil_writer"                 // 编码输出 writer 为 nil
	KeyFSMNilReceiver              MessageID = "fsm.nil_receiver"               // 反序列化接收者为 nil
	KeyFSMTerminalState            MessageID = "fsm.terminal_state"             // 终态不接受任何输入
	KeyFSMExpectedInput            MessageID = "fsm.expected_input"             // 状态仅接受指定输入
	KeyFSMJournalSplitBrain        MessageID = "fsm.journal_split_brain"        // 双代日志脑裂
	KeyFSMJournalRollbackForbidden MessageID = "fsm.journal_rollback_forbidden" // 禁止从损坏高代日志回退旧代
	KeyFSMJournalBothCorrupt       MessageID = "fsm.journal_both_corrupt"       // active 与 staging 日志均损坏
	KeyFSMChunkRemainingExceeded   MessageID = "fsm.chunk_remaining_exceeded"   // 分片长度超出剩余字节
	KeyFSMTimeBeforeStaged         MessageID = "fsm.time_before_staged"         // 操作时刻早于 staged_at
	KeyFSMLeaseNotExpired          MessageID = "fsm.lease_not_expired"          // 租约尚未到期

	// core/domain/inventory 哨兵与上下文错误标识（19 哨兵 + 5 上下文）。
	KeyInventoryInvalidID            MessageID = "inventory.invalid_id"                // 资产标识符无效
	KeyInventoryInvalidKeySpec       MessageID = "inventory.invalid_key_spec"          // 私钥/证书/指纹规格无效
	KeyInventoryInvalidChallengeRule MessageID = "inventory.invalid_challenge_rule"    // 质询应答规则无效
	KeyInventoryInvalidAuthMethod    MessageID = "inventory.invalid_auth_method"       // 认证方式无效
	KeyInventoryAuthCompositeTooDeep MessageID = "inventory.auth_composite_too_deep"   // AuthComposite 嵌套深度超限
	KeyInventoryInvalidNodeOrigin    MessageID = "inventory.invalid_node_origin"       // 节点来源无效
	KeyInventoryInvalidHost          MessageID = "inventory.invalid_host"              // 主机实体无效
	KeyInventoryInvalidIdentity      MessageID = "inventory.invalid_identity"          // 身份实体无效
	KeyInventoryInvalidNode          MessageID = "inventory.invalid_node"              // 节点实体无效
	KeyInventoryInvalidGraph         MessageID = "inventory.invalid_graph"             // 资产配置图无效
	KeyInventoryDuplicateAssetID     MessageID = "inventory.duplicate_asset_id"        // 资产标识或别名碰撞
	KeyInventoryMissingAssetRef      MessageID = "inventory.missing_asset_ref"         // 节点引用缺失主机或身份
	KeyInventoryMissingProxyHop      MessageID = "inventory.missing_proxy_hop"         // ProxyJump 引用不存在跳板
	KeyInventoryProxyJumpCycle       MessageID = "inventory.proxy_jump_cycle"          // 跨命名空间 ProxyJump 环路
	KeyInventoryProxyJumpDepth       MessageID = "inventory.proxy_jump_depth_exceeded" // ProxyJump 跳板深度超限
	KeyInventoryUnknownSecretStore   MessageID = "inventory.unknown_secret_store"      // 凭据引用指向未注册存储
	KeyInventoryInvalidImportBundle  MessageID = "inventory.invalid_import_bundle"     // 格式无关导入包无效
	KeyInventoryNilWriter            MessageID = "inventory.nil_writer"                // 编码输出 writer 为 nil
	KeyInventoryNilReceiver          MessageID = "inventory.nil_receiver"              // 反序列化接收者为 nil
	KeyInventoryCycleDetected        MessageID = "inventory.cycle_detected"            // 检测到跳板环路
	KeyInventoryAliasConflict        MessageID = "inventory.alias_conflict"            // 别名被多个节点占用
	KeyInventoryHopUnknown           MessageID = "inventory.hop_unknown"               // 节点引用未知跳板
	KeyInventoryRegexCompileFailed   MessageID = "inventory.regex_compile_failed"      // 质询正则编译失败
	KeyInvNodeMissingAssetRef        MessageID = "inventory.node_missing_asset_ref"    // 指定节点引用缺失主机或身份资产

	// core/domain/netaddr 哨兵与上下文错误标识（6 哨兵 + 10 上下文）。
	KeyNetaddrInvalidHost       MessageID = "netaddr.invalid_host"        // 网络主机无效
	KeyNetaddrInvalidZone       MessageID = "netaddr.invalid_zone"        // IPv6 区段标识无效
	KeyNetaddrInvalidPort       MessageID = "netaddr.invalid_port"        // 端口号无效
	KeyNetaddrInvalidHostPort   MessageID = "netaddr.invalid_host_port"   // HostPort 无效
	KeyNetaddrInvalidEndpoint   MessageID = "netaddr.invalid_endpoint"    // SSH Endpoint 无效
	KeyNetaddrNilReceiver       MessageID = "netaddr.nil_receiver"        // 反序列化接收者为 nil
	KeyNetaddrBracketsMalformed MessageID = "netaddr.brackets_malformed"  // 方括号地址畸形
	KeyNetaddrHostPortFormat    MessageID = "netaddr.host_port_format"    // 地址不满足 host:port 格式
	KeyNetaddrPortFormat        MessageID = "netaddr.port_format"         // 端口格式或范围非法
	KeyNetaddrHostnameInvalid   MessageID = "netaddr.hostname_invalid"    // 主机名格式校验失败
	KeyNetaddrReasonLength      MessageID = "netaddr.reason.length"       // 主机名原因：长度越界
	KeyNetaddrReasonEdgeDot     MessageID = "netaddr.reason.edge_dot"     // 主机名原因：首尾点号
	KeyNetaddrReasonNumericTLD  MessageID = "netaddr.reason.numeric_tld"  // 主机名原因：末级纯数字标签
	KeyNetaddrReasonLabelLength MessageID = "netaddr.reason.label_length" // 主机名原因：标签长度非法
	KeyNetaddrReasonEdgeHyphen  MessageID = "netaddr.reason.edge_hyphen"  // 主机名原因：标签首尾连字符
	KeyNetaddrReasonIllegalChar MessageID = "netaddr.reason.illegal_char" // 主机名原因：标签含非法字符

	// core/domain/option 哨兵与上下文错误标识（12 哨兵 + 3 上下文）。
	KeyOptionInvalidOption        MessageID = "option.invalid_option"         // OpenSSH 选项无效
	KeyOptionUnknownOption        MessageID = "option.unknown_option"         // 未知或不支持的选项
	KeyOptionInvalidOrigin        MessageID = "option.invalid_origin"         // 策略来源分类无效
	KeyOptionInvalidEndpoint      MessageID = "option.invalid_endpoint"       // 目标端点无效
	KeyOptionInvalidPathList      MessageID = "option.invalid_path_list"      // 路径列表无效
	KeyOptionInvalidAlgoPolicy    MessageID = "option.invalid_algo_policy"    // 算法策略无效
	KeyOptionEmptyAlgorithmList   MessageID = "option.empty_algorithm_list"   // 求解后算法列表为空
	KeyOptionInvalidProxyRoute    MessageID = "option.invalid_proxy_route"    // 代理路由无效
	KeyOptionInvalidControlPolicy MessageID = "option.invalid_control_policy" // 多路复用策略无效
	KeyOptionInvalidEnvFilter     MessageID = "option.invalid_env_filter"     // 环境变量过滤规则无效
	KeyOptionInvalidPercentInput  MessageID = "option.invalid_percent_input"  // OpenSSH 令牌或 %C 输入无效
	KeyOptionNilReceiver          MessageID = "option.nil_receiver"           // 编解码目标为 nil
	KeyOptionQuotedSyntax         MessageID = "option.quoted_syntax"          // 选项引号语法错误
	KeyOptionDurationInvalid      MessageID = "option.duration_invalid"       // OpenSSH 时长格式非法
	KeyOptionTemplateInvalid      MessageID = "option.template_invalid"       // OpenSSH 令牌模板非法

	// core/domain/pathalg 哨兵与上下文错误标识（13 哨兵 + 19 上下文）。
	KeyPathalgInvalidComponent     MessageID = "pathalg.invalid_component"                 // 本地路径分量无效
	KeyPathalgInvalidRemoteName    MessageID = "pathalg.invalid_remote_name"               // 远端名称无效
	KeyPathalgInvalidRemotePath    MessageID = "pathalg.invalid_remote_path"               // 远端路径无效
	KeyPathalgInvalidLocalDest     MessageID = "pathalg.invalid_local_dest"                // 本地沙箱目标路径无效
	KeyPathalgInvalidLocalDir      MessageID = "pathalg.invalid_local_dir"                 // 本地根目录路径无效
	KeyPathalgInvalidLocalSource   MessageID = "pathalg.invalid_local_source"              // 本地只读源路径无效
	KeyPathalgInvalidSymlinkPolicy MessageID = "pathalg.invalid_symlink_policy"            // 软链接策略无效
	KeyPathalgUnsafeSymlink        MessageID = "pathalg.unsafe_symlink"                    // 不安全的符号链接
	KeyPathalgNameCollision        MessageID = "pathalg.name_collision"                    // 路径名存在 Unicode/大小写碰撞
	KeyPathalgInvalidUTF8          MessageID = "pathalg.invalid_utf8"                      // 无效 UTF-8 编码
	KeyPathalgInvalidProtectedRule MessageID = "pathalg.invalid_protected_rule"            // 受保护路径规则无效
	KeyPathalgInvalidGlob          MessageID = "pathalg.invalid_glob"                      // 通配符模式无效
	KeyPathalgNilReceiver          MessageID = "pathalg.nil_receiver"                      // 反序列化接收者为 nil
	KeyPathalgTraversalForbidden   MessageID = "pathalg.traversal_forbidden"               // 禁止目录遍历路径段
	KeyPathalgReservedName         MessageID = "pathalg.reserved_name"                     // 禁止 Windows 保留设备名
	KeyPathalgForbiddenChar        MessageID = "pathalg.forbidden_char"                    // 路径含跨平台禁用字符
	KeyPathalgGlobUnclosed         MessageID = "pathalg.glob_unclosed"                     // 通配符字符类未闭合
	KeyPathalgGlobRangeInvalid     MessageID = "pathalg.glob_range_invalid"                // 通配符字符范围非法
	KeyPathalgReasonSepOrTraversal MessageID = "pathalg.reason.sep_or_traversal"           // 路径原因：含路径分隔符或穿越段
	KeyPathalgReasonEdgeSlash      MessageID = "pathalg.reason.edge_slash"                 // 路径原因：含首尾斜杠
	KeyPathalgReasonDisallowedPfx  MessageID = "pathalg.reason.disallowed_prefix"          // 路径原因：受禁平台路径前缀
	KeyPathalgReasonDriveRelative  MessageID = "pathalg.reason.drive_relative"             // 路径原因：盘符相对路径受禁
	KeyPathalgReasonBareDriveRoot  MessageID = "pathalg.reason.bare_drive_root"            // 路径原因：裸盘符根路径受禁
	KeyPathalgReasonBareRoot       MessageID = "pathalg.reason.bare_root"                  // 路径原因：裸根目录受禁
	KeyPathalgReasonCurrentDir     MessageID = "pathalg.reason.current_dir"                // 路径原因：当前目录 '.' 受禁
	KeyPathalgReasonMustBeAbs      MessageID = "pathalg.reason.must_be_absolute"           // 路径原因：必须为绝对路径
	KeyPathalgReasonAbsRelMismatch MessageID = "pathalg.reason.abs_rel_mismatch"           // 路径原因：绝对与相对路径不匹配
	KeyPathalgReasonUnresolvBase   MessageID = "pathalg.reason.unresolvable_relative_base" // 路径原因：无法基于相对基准路径解析
	KeyPathalgReasonEscapesRoot    MessageID = "pathalg.reason.escapes_root"               // 路径原因：软链目标逃逸沙箱根目录
	KeyPathalgReasonNonRelOrChar   MessageID = "pathalg.reason.non_relative_or_char"       // 路径原因：软链目标非相对路径或含禁用字符
	KeyPathalgReasonAncestorLink   MessageID = "pathalg.reason.ancestor_is_symlink"        // 路径原因：祖先路径分量是软链
	KeyPathalgReasonChainEscapes   MessageID = "pathalg.reason.chain_escapes_root"         // 路径原因：软链解析链逃逸沙箱根目录

	// core/domain/plan 哨兵与上下文错误标识（11 哨兵 + 2 上下文）。
	KeyPlanInvalidDigest          MessageID = "plan.invalid_digest"           // SHA-256 摘要无效
	KeyPlanInvalidTransportPolicy MessageID = "plan.invalid_transport_policy" // 连接传输策略投影无效
	KeyPlanInvalidHopSpec         MessageID = "plan.invalid_hop_spec"         // 单跳连接规格无效
	KeyPlanInvalidConnectionPlan  MessageID = "plan.invalid_connection_plan"  // Merkle 连接计划无效
	KeyPlanTamperedPlanDigest     MessageID = "plan.tampered_plan_digest"     // 连接计划 Merkle 摘要篡改失配
	KeyPlanInvalidHandleKind      MessageID = "plan.invalid_handle_kind"      // 句柄类别无效
	KeyPlanInvalidHandleID        MessageID = "plan.invalid_handle_id"        // 句柄标识无效
	KeyPlanInvalidManagedHandle   MessageID = "plan.invalid_managed_handle"   // 世代托管句柄无效
	KeyPlanNilEntropy             MessageID = "plan.nil_entropy"              // 熵源为 nil
	KeyPlanNilWriter              MessageID = "plan.nil_writer"               // 编码输出 writer 为 nil
	KeyPlanNilReceiver            MessageID = "plan.nil_receiver"             // 反序列化接收者为 nil
	KeyPlanHopIndexDiscontinuous  MessageID = "plan.hop_index_discontinuous"  // 跳板索引不连续
	KeyPlanDigestVerifyFailed     MessageID = "plan.digest_verify_failed"     // 计划摘要校验失败

	// core/domain/playbook 哨兵与上下文错误标识（23 哨兵 + 2 上下文）。
	KeyPlaybookUnsupportedVersion    MessageID = "playbook.unsupported_version"     // Playbook Schema 版本不受支持
	KeyPlaybookInvalidPlaybookID     MessageID = "playbook.invalid_playbook_id"     // PlaybookID 无效
	KeyPlaybookInvalidStepID         MessageID = "playbook.invalid_step_id"         // StepID 无效
	KeyPlaybookInvalidOnErrorPolicy  MessageID = "playbook.invalid_on_error_policy" // OnErrorPolicy 无效
	KeyPlaybookInvalidFileMode       MessageID = "playbook.invalid_file_mode"       // POSIX FileMode 无效
	KeyPlaybookInvalidTargetSelector MessageID = "playbook.invalid_target_selector" // 目标节点选择器无效
	KeyPlaybookInvalidStepAction     MessageID = "playbook.invalid_step_action"     // 步骤动作无效
	KeyPlaybookInvalidEnsureCheck    MessageID = "playbook.invalid_ensure_check"    // Ensure 探测动作非法
	KeyPlaybookNestedEnsureForbidden MessageID = "playbook.nested_ensure_forbidden" // 禁止嵌套 StepEnsure
	KeyPlaybookInvalidStep           MessageID = "playbook.invalid_step"            // 步骤定义无效
	KeyPlaybookDuplicateStepID       MessageID = "playbook.duplicate_step_id"       // 存在重复 StepID
	KeyPlaybookInvalidPlaybook       MessageID = "playbook.invalid_playbook"        // Playbook 定义无效
	KeyPlaybookTamperedDigest        MessageID = "playbook.tampered_digest"         // Playbook 摘要篡改失配
	KeyPlaybookInvalidVar            MessageID = "playbook.invalid_var"             // 环境变量或模板变量非法
	KeyPlaybookInvalidStepStatus     MessageID = "playbook.invalid_step_status"     // 步骤执行状态无效
	KeyPlaybookInvalidNodeStatus     MessageID = "playbook.invalid_node_status"     // 节点汇总状态无效
	KeyPlaybookInvalidStepRecord     MessageID = "playbook.invalid_step_record"     // 步骤执行记录无效
	KeyPlaybookOutcomeStatusMismatch MessageID = "playbook.outcome_status_mismatch" // 执行结果与步骤状态冲突
	KeyPlaybookDuplicateStepRecord   MessageID = "playbook.duplicate_step_record"   // 同节点同步骤执行记录重复
	KeyPlaybookUnknownStepID         MessageID = "playbook.unknown_step_id"         // 记录引用未知 StepID
	KeyPlaybookEmptyReport           MessageID = "playbook.empty_report"            // 执行记录列表为空
	KeyPlaybookNilWriter             MessageID = "playbook.nil_writer"              // 编码输出 writer 为 nil
	KeyPlaybookNilReceiver           MessageID = "playbook.nil_receiver"            // 反序列化接收者为 nil
	KeyPlaybookSelectorOverlap       MessageID = "playbook.selector_overlap"        // 包含与排除选择器重叠
	KeyPlaybookOctalModeInvalid      MessageID = "playbook.octal_mode_invalid"      // 八进制文件权限串非法

	// core/domain/secret 哨兵与上下文错误标识（5 哨兵 + 1 上下文）。
	KeySecretInvalid     MessageID = "secret.invalid"      // SecretBox 无效或未初始化
	KeySecretWiped       MessageID = "secret.wiped"        // SecretBox 已销毁清零
	KeySecretNilCallback MessageID = "secret.nil_callback" // 作用域回调为 nil
	KeySecretInvalidRef  MessageID = "secret.invalid_ref"  // 凭据引用无效
	KeySecretNilReceiver MessageID = "secret.nil_receiver" // 反序列化接收者为 nil
	KeySecretRefFormat   MessageID = "secret.ref_format"   // 凭据引用不满足 store/item 格式

	// core/domain/security 哨兵与上下文错误标识（15 哨兵 + 1 上下文）。
	KeySecurityInvalidVerdict      MessageID = "security.invalid_verdict"           // Verdict 无效
	KeySecurityInvalidRiskLevel    MessageID = "security.invalid_risk_level"        // RiskLevel 无效
	KeySecurityInvalidDecision     MessageID = "security.invalid_decision"          // GuardrailDecision 无效
	KeySecurityInvalidCapability   MessageID = "security.invalid_capability"        // Capability 无效
	KeySecurityInvalidGlob         MessageID = "security.invalid_glob"              // 通配符模式无效
	KeySecurityInvalidNodeOverride MessageID = "security.invalid_node_override"     // NodeOverrides 规则无效
	KeySecurityInvalidTraceID      MessageID = "security.invalid_trace_id"          // TraceID 无效
	KeySecurityInvalidOperationID  MessageID = "security.invalid_operation_id"      // OperationID 无效
	KeySecurityNilEntropy          MessageID = "security.nil_entropy"               // 熵源为 nil
	KeySecurityInvalidDigest       MessageID = "security.invalid_digest"            // SHA-256 Digest 无效
	KeySecurityInvalidBinding      MessageID = "security.invalid_operation_binding" // OperationBinding 无效
	KeySecurityInvalidEnvelope     MessageID = "security.invalid_approval_envelope" // ApprovalEnvelope 无效
	KeySecurityInvalidScope        MessageID = "security.invalid_scope_snapshot"    // ScopeSnapshot 无效
	KeySecurityNilWriter           MessageID = "security.nil_writer"                // 编码输出 writer 为 nil
	KeySecurityNilReceiver         MessageID = "security.nil_receiver"              // 反序列化接收者为 nil
	KeySecurityEscalationReasons   MessageID = "security.escalation_reasons"        // 作用域升级原因非法
)
