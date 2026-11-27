package i18n

import domi18n "github.com/wentf9/xops-cli/core/domain/i18n"

// 本文件声明 CLI 命令族（cli / clikit / cmdssh / cmdtransfer / cmdasset / cmdops）
// 与组合根 cmd/xops 的强类型 MessageID 常量。
// 纯帮助与展示类键仅登记于 rootcatalog.AllKeys()（零 Go 兜底膨胀）；
// 错误、诊断与嵌套标签键登记于 rootcatalog.ErrorKeys() 与 rootcatalog.Lookup。
const (
	// CLI 16 组帮助文档键（纯展示类，仅存于 cli_help.yaml）。
	KeyCLIHelpRoot     domi18n.MessageID = "cli.help.root"     // 根命令帮助文档
	KeyCLIHelpVersion  domi18n.MessageID = "cli.help.version"  // version 命令帮助文档
	KeyCLIHelpSSH      domi18n.MessageID = "cli.help.ssh"      // ssh 命令帮助文档
	KeyCLIHelpExec     domi18n.MessageID = "cli.help.exec"     // exec 命令帮助文档
	KeyCLIHelpTunnel   domi18n.MessageID = "cli.help.tunnel"   // tunnel 命令帮助文档
	KeyCLIHelpMux      domi18n.MessageID = "cli.help.mux"      // mux 命令帮助文档
	KeyCLIHelpSCP      domi18n.MessageID = "cli.help.scp"      // scp 命令帮助文档
	KeyCLIHelpSFTP     domi18n.MessageID = "cli.help.sftp"     // sftp 命令帮助文档
	KeyCLIHelpHosts    domi18n.MessageID = "cli.help.hosts"    // hosts 命令帮助文档
	KeyCLIHelpVault    domi18n.MessageID = "cli.help.vault"    // creds/vault 命令帮助文档
	KeyCLIHelpConfig   domi18n.MessageID = "cli.help.config"   // config 命令帮助文档
	KeyCLIHelpPlaybook domi18n.MessageID = "cli.help.playbook" // playbook 命令帮助文档
	KeyCLIHelpDoctor   domi18n.MessageID = "cli.help.doctor"   // doctor 命令帮助文档
	KeyCLIHelpAudit    domi18n.MessageID = "cli.help.audit"    // audit 命令帮助文档
	KeyCLIHelpMCP      domi18n.MessageID = "cli.help.mcp"      // mcp 命令帮助文档
	KeyCLIHelpTUI      domi18n.MessageID = "cli.help.tui"      // tui 命令帮助文档

	// CLI 人类可读输出、版本标签与诊断摘要键（纯展示类，仅存于 cli.yaml）。
	KeyCLIVersionOutput               domi18n.MessageID = "cli.version.output"                  // version 命令多行版本输出
	KeyCLIShutdownFailed              domi18n.MessageID = "cli.msg.shutdown_failed"             // 引擎逆序停机失败提示
	KeyCLIMarshalJSONFailed           domi18n.MessageID = "cli.msg.marshal_json_failed"         // JSON/v2 编码输出失败提示
	KeyCLICleanupFailed               domi18n.MessageID = "cli.msg.cleanup_failed"              // 隧道或主控清理失败提示
	KeyCLICommandFailed               domi18n.MessageID = "cli.msg.command_failed"              // JSON 错误信封缺省失败文案
	KeyCLIApprovalRequired            domi18n.MessageID = "cli.msg.approval_required"           // 两步审批挑战文本摘要
	KeyCLIRefAsset                    domi18n.MessageID = "cli.msg.ref_asset"                   // 资产反向引用冲突明细行
	KeyCLIRefSecret                   domi18n.MessageID = "cli.msg.ref_secret"                  // 凭据引用冲突明细行
	KeyCLIExitJoinDiag                domi18n.MessageID = "cli.exit.join_diag"                  // 多条退出诊断文本连接模板
	KeyCLISSHMasterActive             domi18n.MessageID = "cli.ssh.master_active"               // ControlMaster 活跃就绪行
	KeyCLISSHForwardListening         domi18n.MessageID = "cli.ssh.forward_listening"           // 端口/套接字转发监听就绪行
	KeyCLIExecBatchSummary            domi18n.MessageID = "cli.exec.batch_summary"              // 批量执行汇总统计行
	KeyCLIExecBatchNodeHeader         domi18n.MessageID = "cli.exec.batch_node_header"          // 批量执行单节点标题行
	KeyCLIExecStatusOK                domi18n.MessageID = "cli.exec.status.ok"                  // 批量执行节点状态：成功
	KeyCLIExecStatusFailed            domi18n.MessageID = "cli.exec.status.failed"              // 批量执行节点状态：失败
	KeyCLIExecStatusNotStarted        domi18n.MessageID = "cli.exec.status.not_started"         // 批量执行节点状态：未启动
	KeyCLIExecStatusCompleted         domi18n.MessageID = "cli.exec.status.completed"           // 批量执行节点状态：已完成
	KeyCLIExecStatusUnknown           domi18n.MessageID = "cli.exec.status.unknown"             // 批量执行节点状态：未知
	KeyCLISCPUploaded                 domi18n.MessageID = "cli.scp.uploaded"                    // SCP 上传完成摘要行
	KeyCLISCPDownloaded               domi18n.MessageID = "cli.scp.downloaded"                  // SCP 下载完成摘要行
	KeyCLISFTPStat                    domi18n.MessageID = "cli.sftp.stat"                       // SFTP stat 元数据展示块
	KeyCLISFTPWrote                   domi18n.MessageID = "cli.sftp.wrote"                      // SFTP 写入完成摘要行
	KeyCLISFTPPatch                   domi18n.MessageID = "cli.sftp.patched"                    // SFTP 补丁替换摘要行
	KeyCLISFTPActionOK                domi18n.MessageID = "cli.sftp.action_ok"                  // SFTP 简单路径操作成功行
	KeyCLISFTPRenamed                 domi18n.MessageID = "cli.sftp.renamed"                    // SFTP 重命名完成摘要行
	KeyCLISFTPChmodOK                 domi18n.MessageID = "cli.sftp.chmod_ok"                   // SFTP 修改权限成功行
	KeyCLISFTPRecoveredOne            domi18n.MessageID = "cli.sftp.recovered_one"              // 单笔传输恢复摘要行
	KeyCLISFTPRecoverUncertainInspect domi18n.MessageID = "cli.sftp.recover_uncertain_inspect"  // 单笔传输不确定提交核验警告
	KeyCLISFTPRecoveredAll            domi18n.MessageID = "cli.sftp.recovered_all"              // 全量传输恢复汇总行
	KeyCLISFTPRecoverEntry            domi18n.MessageID = "cli.sftp.recover_entry"              // 传输恢复单条明细行
	KeyCLISFTPRecoverError            domi18n.MessageID = "cli.sftp.recover_error"              // 传输恢复单条错误行
	KeyCLISFTPRecoverUncertainNoRetry domi18n.MessageID = "cli.sftp.recover_uncertain_no_retry" // 传输不确定提交禁重试警告
	KeyCLIConfigNoFormats             domi18n.MessageID = "cli.config.no_formats"               // 未注册导入格式提示
	KeyCLIConfigImportSummary         domi18n.MessageID = "cli.config.import_summary"           // 配置导入/预览汇总行
	KeyCLIConfigImportLabelPlan       domi18n.MessageID = "cli.config.import_label.plan"        // 配置导入汇总标签：预检计划
	KeyCLIConfigImportLabelImport     domi18n.MessageID = "cli.config.import_label.import"      // 配置导入汇总标签：导入
	KeyCLIConfigImportWarnLine        domi18n.MessageID = "cli.config.import_warn_line"         // 配置导入单条告警明细行
	KeyCLIHostsResolved               domi18n.MessageID = "cli.hosts.resolved"                  // hosts resolve 目标解析结果行
	KeyCLIHostsDAGValid               domi18n.MessageID = "cli.hosts.dag_valid"                 // hosts validate-dag 校验结果行
	KeyCLIHostsFoundRefs              domi18n.MessageID = "cli.hosts.found_refs"                // hosts check-secret-refs 计数行
	KeyCLIHostsMutationOK             domi18n.MessageID = "cli.hosts.mutation_ok"               // 资产增改删成功摘要行
	KeyCLIHostsAllSummary             domi18n.MessageID = "cli.hosts.all_summary"               // hosts list --kind all 汇总行
	KeyCLIVaultStatus                 domi18n.MessageID = "cli.vault.status"                    // 凭据库状态摘要行
	KeyCLIVaultStatusDetail           domi18n.MessageID = "cli.vault.status_detail"             // 凭据库状态含详情摘要行
	KeyCLIVaultActionOK               domi18n.MessageID = "cli.vault.action_ok"                 // 凭据库初始化/解锁成功行
	KeyCLIVaultLocked                 domi18n.MessageID = "cli.vault.locked"                    // 凭据库锁定成功行
	KeyCLIVaultDoctorSummary          domi18n.MessageID = "cli.vault.doctor_summary"            // 凭据库健康诊断汇总行
	KeyCLIVaultSagaResult             domi18n.MessageID = "cli.vault.saga_result"               // 凭据库 Saga 终态摘要行
	KeyCLIVaultSagaUncertain          domi18n.MessageID = "cli.vault.saga_uncertain"            // 凭据库 Saga 不确定持久性警告
	KeyCLIVaultRefsSummary            domi18n.MessageID = "cli.vault.refs_summary"              // 凭据引用检索汇总行
	KeyCLIVaultDeleted                domi18n.MessageID = "cli.vault.deleted"                   // 凭据删除成功行
	KeyCLIVaultGCComplete             domi18n.MessageID = "cli.vault.gc_complete"               // 未引用凭据安全回收汇总行
	KeyCLIVaultEnrolled               domi18n.MessageID = "cli.vault.enrolled"                  // 加密私钥身份录入成功行
	KeyCLIAuditReconcileSummary       domi18n.MessageID = "cli.audit.reconcile_summary"         // 崩溃审计对账汇总行
	KeyCLIAuditEntriesSummary         domi18n.MessageID = "cli.audit.entries_summary"           // 审计记录检索汇总行
	KeyCLIDoctorVaultNoCap            domi18n.MessageID = "cli.doctor.vault_no_cap"             // 运行器不支持凭据库诊断提示
	KeyCLIDoctorVaultNotConfigured    domi18n.MessageID = "cli.doctor.vault_not_configured"     // 凭据库未配置提示
	KeyCLIDoctorSummary               domi18n.MessageID = "cli.doctor.summary"                  // 系统诊断总览行
	KeyCLIDoctorInventory             domi18n.MessageID = "cli.doctor.inventory"                // 资产诊断分节汇总行
	KeyCLIDoctorVault                 domi18n.MessageID = "cli.doctor.vault"                    // 凭据库诊断分节汇总行
	KeyCLIDoctorVaultNote             domi18n.MessageID = "cli.doctor.vault_note"               // 凭据库诊断附加说明行
	KeyCLIDoctorSevInfo               domi18n.MessageID = "cli.doctor.sev.info"                 // 诊断严重度标签：提示
	KeyCLIDoctorSevWarn               domi18n.MessageID = "cli.doctor.sev.warn"                 // 诊断严重度标签：警告
	KeyCLIDoctorSevError              domi18n.MessageID = "cli.doctor.sev.error"                // 诊断严重度标签：错误
	KeyCLIDoctorFindingLine           domi18n.MessageID = "cli.doctor.finding_line"             // 诊断发现明细行（无主题）
	KeyCLIDoctorFindingLineSubj       domi18n.MessageID = "cli.doctor.finding_line_subject"     // 诊断发现明细行（含主题）
	KeyCLIPlaybookValid               domi18n.MessageID = "cli.playbook.valid"                  // Playbook 离线校验通过行
	KeyCLIPlaybookSummary             domi18n.MessageID = "cli.playbook.summary"                // Playbook 执行汇总行
	KeyCLIPlaybookUnknownWarning      domi18n.MessageID = "cli.playbook.unknown_warning"        // Playbook 含未知终态步骤警告

	// CLI 5 个核心哨兵与运行期配置错误键（规范英文兜底登记于 internal/rootcatalog）。
	KeyCLIInvalidConfig           domi18n.MessageID = "cli.err.invalid_config"            // 无效的 AppConfig 配置（哨兵）
	KeyCLIAppNotInitialized       domi18n.MessageID = "cli.err.app_not_initialized"       // App 未初始化（哨兵）
	KeyCLIUsage                   domi18n.MessageID = "cli.err.usage"                     // 命令行参数无效（哨兵）
	KeyCLINotConfigured           domi18n.MessageID = "cli.err.not_configured"            // 宿主未注入能力回调（哨兵）
	KeyCLIUnsupportedRunner       domi18n.MessageID = "cli.err.unsupported_runner"        // Engine Runner 不支持能力（哨兵）
	KeyCLINilContext              domi18n.MessageID = "cli.err.nil_context"               // CLI 上下文为 nil
	KeyCLINilEngineFactory        domi18n.MessageID = "cli.err.nil_engine_factory"        // EngineFactory 为 nil
	KeyCLINilStdStreams           domi18n.MessageID = "cli.err.nil_std_streams"           // Stdout 或 Stderr 为 nil
	KeyCLIShutdownTimeoutPositive domi18n.MessageID = "cli.err.shutdown_timeout_positive" // ShutdownTimeout 非正时长
	KeyCLINilSessionRunner        domi18n.MessageID = "cli.err.nil_session_runner"        // EngineFactory 返回 nil SessionRunner
	KeyCLICapabilityRequired      domi18n.MessageID = "cli.err.capability_required"       // 缺少指定引擎能力窄接口
	KeyCLIHookNotConfigured       domi18n.MessageID = "cli.err.hook_not_configured"       // 指定宿主回调未注入
	KeyCLIInputTooLarge           domi18n.MessageID = "cli.err.input_too_large"           // 本地/标准输入超出字节上限

	// CLI 通用标志、参数解析与用法错误键。
	KeyCLIUnknownCommand         domi18n.MessageID = "cli.err.unknown_command"           // 未知顶级子命令
	KeyCLIUnknownSubcommand      domi18n.MessageID = "cli.err.unknown_subcommand"        // 未知命令族子命令
	KeyCLIHelpTooManyTopics      domi18n.MessageID = "cli.err.help_too_many_topics"      // help 参数超过 1 个主题
	KeyCLIUnknownHelpTopic       domi18n.MessageID = "cli.err.unknown_help_topic"        // 未知帮助主题
	KeyCLIVersionInvalidArg      domi18n.MessageID = "cli.err.version_invalid_arg"       // version 不接受该参数
	KeyCLIMissingShortValue      domi18n.MessageID = "cli.err.missing_short_value"       // 短选项缺少参数值
	KeyCLIMissingLongValue       domi18n.MessageID = "cli.err.missing_long_value"        // 长选项缺少参数值
	KeyCLIHelpNoValue            domi18n.MessageID = "cli.err.help_no_value"             // --help 不接受参数值
	KeyCLIUnknownShortFlag       domi18n.MessageID = "cli.err.unknown_short_flag"        // 未知短选项
	KeyCLIUnknownLongFlag        domi18n.MessageID = "cli.err.unknown_long_flag"         // 未知长选项或参数
	KeyCLIUnexpectedArg          domi18n.MessageID = "cli.err.unexpected_arg"            // 多余位置参数
	KeyCLIEmptyConfigFile        domi18n.MessageID = "cli.err.empty_config_file"         // -F 配置文件路径为空
	KeyCLIInvalidBoolFlag        domi18n.MessageID = "cli.err.invalid_bool_flag"         // 布尔选项取值非法
	KeyCLIInvalidPositiveInt     domi18n.MessageID = "cli.err.invalid_positive_int"      // 选项需要正整数
	KeyCLIInvalidNonNegInt       domi18n.MessageID = "cli.err.invalid_nonneg_int"        // 选项需要非负整数
	KeyCLIInvalidDuration        domi18n.MessageID = "cli.err.invalid_duration"          // 选项需要正时长
	KeyCLIEmptyPerm              domi18n.MessageID = "cli.err.empty_perm"                // 权限参数为空
	KeyCLIInvalidOctalPerm       domi18n.MessageID = "cli.err.invalid_octal_perm"        // 八进制权限位非法
	KeyCLIInvalidKeyValue        domi18n.MessageID = "cli.err.invalid_key_value"         // 选项需要 KEY=VALUE 格式
	KeyCLIInvalidFlagValue       domi18n.MessageID = "cli.err.invalid_flag_value"        // 选项参数取值非法
	KeyCLIInvalidFlagValueEnum   domi18n.MessageID = "cli.err.invalid_flag_value_enum"   // 枚举选项取值不在允许集合内
	KeyCLIInvalidField           domi18n.MessageID = "cli.err.invalid_field"             // 命名字段或路径取值非法
	KeyCLIInvalidLaunchProfile   domi18n.MessageID = "cli.err.invalid_launch_profile"    // 启动配置组合非法
	KeyCLIInvalidOptionLayer     domi18n.MessageID = "cli.err.invalid_option_layer"      // CLI 选项层校验失败
	KeyCLIMissingRequiredFlag    domi18n.MessageID = "cli.err.missing_required_flag"     // 缺少必需选项
	KeyCLIMutuallyExclusiveFlags domi18n.MessageID = "cli.err.mutually_exclusive_flags"  // 互斥选项同时指定
	KeyCLIExactlyOneFlagRequired domi18n.MessageID = "cli.err.exactly_one_flag_required" // 须二选一指定互斥选项
	KeyCLIArgCountExact          domi18n.MessageID = "cli.err.arg_count_exact"           // 位置参数个数不满足精确要求
	KeyCLIArgCountAtLeast        domi18n.MessageID = "cli.err.arg_count_at_least"        // 位置参数个数不足下限
	KeyCLIInteractiveNoJSON      domi18n.MessageID = "cli.err.interactive_no_json"       // 交互式入口不支持 --json 输出

	// CLI 远端执行退出码与结果终态诊断错误键（clikit/exitcode.go）。
	KeyCLIExitInvalidOutcome       domi18n.MessageID = "cli.exit.invalid_outcome"        // 无效的执行终态对象
	KeyCLIExitUnexpectedOutcome    domi18n.MessageID = "cli.exit.unexpected_outcome"     // 非预期的执行终态类型
	KeyCLIExitInvalidStatus        domi18n.MessageID = "cli.exit.invalid_status"         // 无效的远端退出状态
	KeyCLIExitUnreadableCode       domi18n.MessageID = "cli.exit.unreadable_code"        // 无法读取远端退出码
	KeyCLIExitUnexpectedStatus     domi18n.MessageID = "cli.exit.unexpected_status"      // 非预期的退出状态类型
	KeyCLIExitSignal               domi18n.MessageID = "cli.exit.signal"                 // 远端进程被信号终止
	KeyCLIExitSignalCore           domi18n.MessageID = "cli.exit.signal_core"            // 远端进程被信号终止并核心转储
	KeyCLIExitSignalMsg            domi18n.MessageID = "cli.exit.signal_msg"             // 远端进程被信号终止（含消息）
	KeyCLIExitSignalCoreMsg        domi18n.MessageID = "cli.exit.signal_core_msg"        // 远端进程被信号终止并核心转储（含消息）
	KeyCLIExitUnknown              domi18n.MessageID = "cli.exit.unknown_status"         // 远端进程退出但无退出码
	KeyCLIExitUnknownReason        domi18n.MessageID = "cli.exit.unknown_status_reason"  // 远端进程退出但无退出码（含原因）
	KeyCLIExitNotStarted           domi18n.MessageID = "cli.exit.not_started"            // SSH 启动前失败
	KeyCLIExitNotStartedReason     domi18n.MessageID = "cli.exit.not_started_reason"     // SSH 启动前失败（含原因）
	KeyCLIExitOutcomeUnknown       domi18n.MessageID = "cli.exit.outcome_unknown"        // SSH 结果未知（禁止盲目重试）
	KeyCLIExitOutcomeUnknownReason domi18n.MessageID = "cli.exit.outcome_unknown_reason" // SSH 结果未知（含原因，禁止盲目重试）

	// CLI 各命令族专属校验与执行错误键（cmdssh / cmdtransfer / cmdasset / cmdops）。
	KeyCLIForwardEmpty              domi18n.MessageID = "cli.err.forward_empty"                // 转发规格为空
	KeyCLIForwardInvalidDir         domi18n.MessageID = "cli.err.forward_invalid_dir"          // 转发方向不受支持
	KeyCLIForwardInvalidSpec        domi18n.MessageID = "cli.err.forward_invalid_spec"         // 转发规格语法非法
	KeyCLIForwardInvalidPort        domi18n.MessageID = "cli.err.forward_invalid_port"         // 转发端口非法
	KeyCLITUNEmpty                  domi18n.MessageID = "cli.err.tun_empty"                    // -w TUN 规格为空
	KeyCLITUNInvalidUnit            domi18n.MessageID = "cli.err.tun_invalid_unit"             // TUN 设备编号非法
	KeyCLISSHMissingTarget          domi18n.MessageID = "cli.err.ssh_missing_target"           // ssh 缺少目标主机
	KeyCLISSHFlagConflictCmd        domi18n.MessageID = "cli.err.ssh_flag_conflict_cmd"        // 选项与远端命令参数冲突
	KeyCLISSHControlConflictBg      domi18n.MessageID = "cli.err.ssh_control_conflict_bg"      // -O 与 -f 后台模式冲突
	KeyCLISSHBgRequiresForward      domi18n.MessageID = "cli.err.ssh_bg_requires_forward"      // -f 后台模式缺少 -N/-M 或转发
	KeyCLISSHNoCmdRequiresForward   domi18n.MessageID = "cli.err.ssh_nocmd_requires_forward"   // -N 模式缺少 -M 或转发
	KeyCLISSHStdioFwdUnsupported    domi18n.MessageID = "cli.err.ssh_stdio_fwd_unsupported"    // -W stdio 转发暂不支持
	KeyCLIMuxRequiresSingleForward  domi18n.MessageID = "cli.err.mux_requires_single_forward"  // mux forward/cancel 需恰好一条转发规则
	KeyCLITunnelRequiresForward     domi18n.MessageID = "cli.err.tunnel_requires_forward"      // tunnel 缺少转发规则
	KeyCLIExecMissingTarget         domi18n.MessageID = "cli.err.exec_missing_target"          // exec 缺少目标主机或选择器
	KeyCLIExecMissingCommand        domi18n.MessageID = "cli.err.exec_missing_command"         // exec 缺少待执行远端命令
	KeyCLIExecBatchPrivUnsupported  domi18n.MessageID = "cli.err.exec_batch_priv_unsupported"  // 批量 exec 不支持交互提权
	KeyCLIExecPlanFailed            domi18n.MessageID = "cli.err.exec_plan_failed"             // 构造 CommandPlan 失败
	KeyCLIExecSelectorInvalid       domi18n.MessageID = "cli.err.exec_selector_invalid"        // 目标选择器非法
	KeyCLISCPEndpointMismatch       domi18n.MessageID = "cli.err.scp_endpoint_mismatch"        // scp 源与目标须一端本地一端远端
	KeyCLISCPDownloadSymlinkPolicy  domi18n.MessageID = "cli.err.scp_download_symlink_policy"  // scp 下载软链策略受限
	KeyCLISCPRecursiveSymlinkPolicy domi18n.MessageID = "cli.err.scp_recursive_symlink_policy" // 递归上传软链策略受限
	KeyCLISCPLocalRootRelative      domi18n.MessageID = "cli.err.scp_local_root_relative"      // --local-root 模式须传相对路径
	KeyCLISCPRecursiveDotAbs        domi18n.MessageID = "cli.err.scp_recursive_dot_abs"        // 递归上传 '.' 需要绝对工作目录或 --local-root
	KeyCLISCPNoRemoteBase           domi18n.MessageID = "cli.err.scp_no_remote_base"           // 远端路径无文件名组件
	KeyCLISFTPRecoverUsage          domi18n.MessageID = "cli.err.sftp_recover_usage"           // sftp recover 参数个数非法
	KeyCLIVaultIdentityExists       domi18n.MessageID = "cli.err.vault_identity_exists"        // 身份已存在（可传 --replace）
	KeyCLIVaultNodeNotFound         domi18n.MessageID = "cli.err.vault_node_not_found"         // 目标节点不存在
	KeyCLIPlaybookDecodeFailed      domi18n.MessageID = "cli.err.playbook_decode_failed"       // 解析 Playbook 文档失败
	KeyCLIPlaybookEmpty             domi18n.MessageID = "cli.err.playbook_empty"               // Playbook 输入为空
	KeyCLIPlaybookMustBeObject      domi18n.MessageID = "cli.err.playbook_must_be_object"      // Playbook 顶层文档须为对象
	KeyCLIPlaybookYAMLFailed        domi18n.MessageID = "cli.err.playbook_yaml_failed"         // Playbook YAML 解码失败
	KeyCLIPlaybookYAMLDupKey        domi18n.MessageID = "cli.err.playbook_yaml_dup_key"        // Playbook YAML 存在重复键
	KeyCLIPlaybookYAMLNoAlias       domi18n.MessageID = "cli.err.playbook_yaml_no_alias"       // Playbook YAML 禁止使用别名

	// 组合根 cmd/xops 配置、宿主装配与钩子错误键。
	KeyCmdConfigDecodeFailed      domi18n.MessageID = "cmd.err.config_decode_failed"      // 配置字段解码失败
	KeyCmdConfigInvalidValue      domi18n.MessageID = "cmd.err.config_invalid_value"      // 配置字段取值非法
	KeyCmdAuditLogInHomeDir       domi18n.MessageID = "cmd.err.audit_log_in_home_dir"     // 审计日志根路径禁止直放家目录
	KeyCmdEnvNotInitialized       domi18n.MessageID = "cmd.err.env_not_initialized"       // 环境包装器未初始化
	KeyCmdResolveDirFailed        domi18n.MessageID = "cmd.err.resolve_dir_failed"        // 解析宿主目录或本地身份失败
	KeyCmdInvalidDirPath          domi18n.MessageID = "cmd.err.invalid_dir_path"          // 宿主目录或配置路径非法
	KeyCmdOpenSSHConfigUnreadable domi18n.MessageID = "cmd.err.openssh_config_unreadable" // 显式 OpenSSH 配置文件不可读
	KeyCmdTakeoverInvalidOutcome  domi18n.MessageID = "cmd.err.takeover_invalid_outcome"  // TUI 接管交互会话返回无效终态
	KeyCmdTakeoverNotStarted      domi18n.MessageID = "cmd.err.takeover_not_started"      // TUI 接管交互会话启动前失败
	KeyCmdTakeoverOutcomeUnknown  domi18n.MessageID = "cmd.err.takeover_outcome_unknown"  // TUI 接管交互会话终态未知
	KeyCmdAuditReadFailed         domi18n.MessageID = "cmd.err.audit_read_failed"         // 读取本地审计日志失败
	KeyCmdAuditLineInvalid        domi18n.MessageID = "cmd.err.audit_line_invalid"        // 本地审计日志行格式非法
	KeyCmdFileTooLarge            domi18n.MessageID = "cmd.err.file_too_large"            // 操作员文件超出最大允许大小
	KeyCmdFileSizeExceedsLimit    domi18n.MessageID = "cmd.err.file_size_exceeds_limit"   // 操作员文件声明体积超限
	KeyCmdShutdownStageFailed     domi18n.MessageID = "cmd.err.shutdown_stage_failed"     // 逆序停机指定阶段失败
	KeyCmdVaultUnknownDefault     domi18n.MessageID = "cmd.err.vault_unknown_default"     // vault.default_store 未知
	KeyCmdVaultUnsupportedKind    domi18n.MessageID = "cmd.err.vault_unsupported_kind"    // 不支持的凭据库后端类型
	KeyCmdInitComponentFailed     domi18n.MessageID = "cmd.err.init_component_failed"     // 宿主组件初始化失败
	KeyCmdLoadConfigFailed        domi18n.MessageID = "cmd.err.load_config_failed"        // 加载 config.yaml 失败
	KeyCmdReconcileFailed         domi18n.MessageID = "cmd.err.reconcile_failed"          // 启动期崩溃审计对账失败

	// CLI 参数字段嵌套标签键（用于 KeyCLIInvalidField 嵌套 i18n.Msg 参数，规范英文兜底登记于 internal/rootcatalog）。
	KeyCLIFieldLocalFilePath     domi18n.MessageID = "cli.field.local_file_path"     // 字段标签：本地文件路径
	KeyCLIFieldControlSocketPath domi18n.MessageID = "cli.field.control_socket_path" // 字段标签：控制套接字路径
	KeyCLIFieldRemoteDestPath    domi18n.MessageID = "cli.field.remote_dest_path"    // 字段标签：远端目标路径
	KeyCLIFieldRemoteSourcePath  domi18n.MessageID = "cli.field.remote_source_path"  // 字段标签：远端源路径
	KeyCLIFieldLocalSourcePath   domi18n.MessageID = "cli.field.local_source_path"   // 字段标签：本地源路径
	KeyCLIFieldLocalRelPath      domi18n.MessageID = "cli.field.local_rel_path"      // 字段标签：本地相对路径
	KeyCLIFieldLocalDirName      domi18n.MessageID = "cli.field.local_dir_name"      // 字段标签：本地目录名
	KeyCLIFieldLocalDestPath     domi18n.MessageID = "cli.field.local_dest_path"     // 字段标签：本地目标路径
	KeyCLIFieldLocalDestFilename domi18n.MessageID = "cli.field.local_dest_filename" // 字段标签：本地目标文件名
	KeyCLIFieldLocalDestRelPath  domi18n.MessageID = "cli.field.local_dest_rel_path" // 字段标签：本地目标相对路径
	KeyCLIFieldRemotePath        domi18n.MessageID = "cli.field.remote_path"         // 字段标签：远端路径
	KeyCLIFieldOldPath           domi18n.MessageID = "cli.field.old_path"            // 字段标签：旧路径
	KeyCLIFieldNewPath           domi18n.MessageID = "cli.field.new_path"            // 字段标签：新路径
	KeyCLIFieldTransferID        domi18n.MessageID = "cli.field.transfer_id"         // 字段标签：传输 ID
	KeyCLIFieldTag               domi18n.MessageID = "cli.field.tag"                 // 字段标签：标签
	KeyCLIFieldAlias             domi18n.MessageID = "cli.field.alias"               // 字段标签：别名
	KeyCLIFieldSecretRef         domi18n.MessageID = "cli.field.secret_ref"          // 字段标签：凭据引用

	// 组合根 cmd/xops 目标目录与配置路径嵌套标签键（用于 KeyCmdResolveDirFailed / KeyCmdInvalidDirPath）。
	KeyCmdTargetAuditLogDir      domi18n.MessageID = "cmd.target.audit_log_dir"      // 目标标签：审计日志目录
	KeyCmdTargetAuditLogFile     domi18n.MessageID = "cmd.target.audit_log_file"     // 目标标签：审计日志文件
	KeyCmdTargetLocalIdentity    domi18n.MessageID = "cmd.target.local_identity"     // 目标标签：本机身份
	KeyCmdTargetHomeDir          domi18n.MessageID = "cmd.target.home_dir"           // 目标标签：用户主目录
	KeyCmdTargetDefaultStateDir  domi18n.MessageID = "cmd.target.default_state_dir"  // 目标标签：默认状态目录
	KeyCmdTargetDefaultSSHDir    domi18n.MessageID = "cmd.target.default_ssh_dir"    // 目标标签：默认 .ssh 目录
	KeyCmdTargetDefaultSSHConfig domi18n.MessageID = "cmd.target.default_ssh_config" // 目标标签：默认 SSH 配置文件
	KeyCmdTargetOpenSSHConfig    domi18n.MessageID = "cmd.target.openssh_config"     // 目标标签：OpenSSH 配置
	KeyCmdTargetInitialRemoteDir domi18n.MessageID = "cmd.target.initial_remote_dir" // 目标标签：初始远端目录
	KeyCmdTargetWorkingDir       domi18n.MessageID = "cmd.target.working_dir"        // 目标标签：工作目录
	KeyCmdTargetDefaultVaultDir  domi18n.MessageID = "cmd.target.default_vault_dir"  // 目标标签：默认凭据库目录
	KeyCmdTargetVaultStore       domi18n.MessageID = "cmd.target.vault_store"        // 目标标签：命名凭据库存储（含 {name}）

	// 组合根 cmd/xops 宿主组件嵌套标签键（用于 KeyCmdInitComponentFailed）。
	KeyCmdCompInventoryStore        domi18n.MessageID = "cmd.comp.inventory_store"         // 组件标签：资产存储
	KeyCmdCompWALJournalStore       domi18n.MessageID = "cmd.comp.wal_journal_store"       // 组件标签：WAL 日志存储
	KeyCmdCompTerminalAdapter       domi18n.MessageID = "cmd.comp.terminal_adapter"        // 组件标签：终端适配器
	KeyCmdCompInteractionAdapter    domi18n.MessageID = "cmd.comp.interaction_adapter"     // 组件标签：交互适配器
	KeyCmdCompSSHFPLookupAdapter    domi18n.MessageID = "cmd.comp.sshfp_lookup_adapter"    // 组件标签：SSHFP 查询适配器
	KeyCmdCompOpenSSHImporter       domi18n.MessageID = "cmd.comp.openssh_importer"        // 组件标签：OpenSSH 导入器
	KeyCmdCompCSVImporter           domi18n.MessageID = "cmd.comp.csv_importer"            // 组件标签：CSV 导入器
	KeyCmdCompProcessInstanceID     domi18n.MessageID = "cmd.comp.process_instance_id"     // 组件标签：进程实例 ID
	KeyCmdCompAuditSink             domi18n.MessageID = "cmd.comp.audit_sink"              // 组件标签：审计落盘器
	KeyCmdCompAuditReconciler       domi18n.MessageID = "cmd.comp.audit_reconciler"        // 组件标签：审计对账器
	KeyCmdCompDefaultOfflineVault   domi18n.MessageID = "cmd.comp.default_offline_vault"   // 组件标签：默认离线凭据库
	KeyCmdCompPlatformKeychainVault domi18n.MessageID = "cmd.comp.platform_keychain_vault" // 组件标签：平台 os_keychain 凭据库
	KeyCmdCompRouterVault           domi18n.MessageID = "cmd.comp.router_vault"            // 组件标签：路由凭据库
	KeyCmdCompConfiguredRouterVault domi18n.MessageID = "cmd.comp.configured_router_vault" // 组件标签：已配置路由凭据库
	KeyCmdCompOfflineAEADVault      domi18n.MessageID = "cmd.comp.offline_aead_vault"      // 组件标签：offline_aead 凭据库（含 {name}）
	KeyCmdCompOSKeychainVault       domi18n.MessageID = "cmd.comp.os_keychain_vault"       // 组件标签：os_keychain 凭据库（含 {name}）
	KeyCmdCompExternalHelperVault   domi18n.MessageID = "cmd.comp.external_helper_vault"   // 组件标签：external_helper 凭据库（含 {name}）
)
