package i18n

import domi18n "github.com/wentf9/xops-cli/core/domain/i18n"

// 本文件声明本地宿主适配器层（internal/host/{audit,openssh,store,store/yamlcodec,sys,sys/agent,sys/sshfp,sys/tun,vault/**}）
// 的全部强类型结构化错误与哨兵 MessageID 常量。
// 所有常量均登记于 internal/rootcatalog（经 RootErrorKeys() 与 rootFallback 暴露），
// 并与 locales/{en,zh}/host.yaml 保持 100% 键双射、占位符一致与规范英文兜底逐字相等。
const (
	// 宿主层跨包共享通用校验、路径与 I/O 错误键（14 个）。
	KeyHostNotInitialized         domi18n.MessageID = "host.common.not_initialized"            // 宿主组件尚未初始化
	KeyHostNilDependency          domi18n.MessageID = "host.common.nil_dependency"             // 必选依赖或流句柄为空
	KeyHostInvalidField           domi18n.MessageID = "host.common.invalid_field"              // 指定字段或参数对象无效
	KeyHostInvalidSecretRef       domi18n.MessageID = "host.common.invalid_secret_ref"         // 凭据引用无效
	KeyHostInvalidSecretBox       domi18n.MessageID = "host.common.invalid_secret_box"         // SecretBox 无效
	KeyHostLimitOutOfRange        domi18n.MessageID = "host.common.limit_out_of_range"         // 数值上限配置超出允许范围
	KeyHostDurationMustBePositive domi18n.MessageID = "host.common.duration_must_be_positive"  // 时长字段必须为正值
	KeyHostValueMustBeNonNegative domi18n.MessageID = "host.common.value_must_be_non_negative" // 数值字段不能为负
	KeyHostValueMustBeNonZero     domi18n.MessageID = "host.common.value_must_be_non_zero"     // 数值字段不能为 0
	KeyHostPathIsSymlink          domi18n.MessageID = "host.common.path_is_symlink"            // 沙箱路径为符号链接
	KeyHostPathNotDir             domi18n.MessageID = "host.common.path_not_dir"               // 沙箱路径不是目录
	KeyHostPathNotRegular         domi18n.MessageID = "host.common.path_not_regular"           // 沙箱路径不是常规文件
	KeyHostSizeExceedsLimit       domi18n.MessageID = "host.common.size_exceeds_limit"         // 输入或文件大小超出字节上限
	KeyHostReadFailed             domi18n.MessageID = "host.common.read_failed"                // 读取本地配置文件失败

	// 审计日志与崩溃对账适配器错误键（internal/host/audit，6 个）。
	KeyHostAuditCorruptLog          domi18n.MessageID = "host.audit.corrupt_log"           // 审计日志记录损坏（哨兵）
	KeyHostAuditUnreconciledLock    domi18n.MessageID = "host.audit.unreconciled_lock"     // 进程锁文件含未对账残留记录
	KeyHostAuditLockIOFailed        domi18n.MessageID = "host.audit.lock_io_failed"        // 进程锁日志读写定位刷盘失败
	KeyHostAuditLockCompactFailed   domi18n.MessageID = "host.audit.lock_compact_failed"   // 排空后截断压缩进程锁失败
	KeyHostAuditLineUnmarshalFailed domi18n.MessageID = "host.audit.line_unmarshal_failed" // 审计日志单行反序列化失败
	KeyHostAuditAppendAbortedFailed domi18n.MessageID = "host.audit.append_aborted_failed" // 补写 AbortedByCrash 记录失败

	// OpenSSH 只读配置解析器错误与流式诊断键（internal/host/openssh，21 个）。
	KeyHostOpenSSHIncludeCycle             domi18n.MessageID = "host.openssh.include_cycle"                // Include 循环引用（哨兵）
	KeyHostOpenSSHIncludeDepthExceeded     domi18n.MessageID = "host.openssh.include_depth_exceeded"       // Include 嵌套深度超限（哨兵）
	KeyHostOpenSSHInvalidConfig            domi18n.MessageID = "host.openssh.invalid_config"               // OpenSSH 配置或指令非法（哨兵）
	KeyHostOpenSSHIncludeNeedsHome         domi18n.MessageID = "host.openssh.include_needs_home"           // 展开 ~/ Include 路径需要有效 HomeDir
	KeyHostOpenSSHIncludeGlobNeedsFS       domi18n.MessageID = "host.openssh.include_glob_needs_fs"        // 通配符 Include 需要提供 ScopedFS
	KeyHostOpenSSHIncludeGlobDotDot        domi18n.MessageID = "host.openssh.include_glob_dotdot"          // 通配符 Include 禁止包含 '..' 段
	KeyHostOpenSSHInvalidGlob              domi18n.MessageID = "host.openssh.invalid_glob"                 // Include 通配符模式语法非法
	KeyHostOpenSSHMatchMissingCriteria     domi18n.MessageID = "host.openssh.match_missing_criteria"       // Match 指令缺少有效条件
	KeyHostOpenSSHMatchModifierInvalid     domi18n.MessageID = "host.openssh.match_modifier_invalid"       // Match all/canonical/final 用法非法
	KeyHostOpenSSHMatchCriterionMissingArg domi18n.MessageID = "host.openssh.match_criterion_missing_arg"  // Match 条件缺少参数
	KeyHostOpenSSHIncludeDepthAt           domi18n.MessageID = "host.openssh.include_depth_at"             // 指定路径处 Include 深度超限
	KeyHostOpenSSHIncludeCycleAt           domi18n.MessageID = "host.openssh.include_cycle_at"             // 指定路径处检测到 Include 循环
	KeyHostOpenSSHIncludeFilesExceeded     domi18n.MessageID = "host.openssh.include_files_exceeded"       // Include 加载文件总数超限
	KeyHostOpenSSHFileTooLarge             domi18n.MessageID = "host.openssh.file_too_large"               // 配置文件大小超过上限
	KeyHostOpenSSHLineError                domi18n.MessageID = "host.openssh.line_error"                   // 指定文件与行号处的语法错误
	KeyHostOpenSSHInvalidClause            domi18n.MessageID = "host.openssh.invalid_clause"               // 指定行 Host/Match/Include 指令非法
	KeyHostOpenSSHDirectiveMissingValue    domi18n.MessageID = "host.openssh.directive_missing_value"      // 指令缺少参数值
	KeyHostOpenSSHUnclosedQuote            domi18n.MessageID = "host.openssh.unclosed_quote"               // 存在未闭合引号
	KeyHostOpenSSHDiagIncludeSkip          domi18n.MessageID = "host.openssh.diag.include_skipped"         // 流式解析诊断：跳过 Include 展开
	KeyHostOpenSSHDiagMatchCanon           domi18n.MessageID = "host.openssh.diag.match_canonical_ignored" // 流式解析诊断：忽略 Match canonical 块
	KeyHostOpenSSHDiagMatchExec            domi18n.MessageID = "host.openssh.diag.match_exec_ignored"      // 流式解析诊断：忽略 Match exec 块

	// 资产持久化、WAL 日志与 CSV/OpenSSH 导入器错误及告警键（internal/host/store，29 个）。
	KeyHostStoreUnsupportedSchema        domi18n.MessageID = "host.store.unsupported_schema_version"           // 不受支持的配置 schema 版本（哨兵）
	KeyHostStorePlaintextSecretForbidden domi18n.MessageID = "host.store.plaintext_secret_forbidden"           // 禁止明文密码或机密列（哨兵）
	KeyHostStoreInvalidCSV               domi18n.MessageID = "host.store.invalid_csv"                          // CSV 导入格式或字段非法（哨兵）
	KeyHostStoreCorruptJournalFrame      domi18n.MessageID = "host.store.corrupt_journal_frame"                // WAL 帧格式或 CRC32 校验失败（哨兵）
	KeyHostStoreCSVEmpty                 domi18n.MessageID = "host.store.csv_empty"                            // CSV 输入为空或缺少数据行
	KeyHostStoreCSVTooManyRows           domi18n.MessageID = "host.store.csv_too_many_rows"                    // CSV 行数超过上限
	KeyHostStoreCSVForbiddenColumn       domi18n.MessageID = "host.store.csv_forbidden_column"                 // CSV 表头包含禁止的明文机密列
	KeyHostStoreCSVDupOrEmptyColumn      domi18n.MessageID = "host.store.csv_dup_or_empty_column"              // CSV 表头包含空列或重复列
	KeyHostStoreCSVMissingReqColumns     domi18n.MessageID = "host.store.csv_missing_required_columns"         // CSV 表头缺少必需列
	KeyHostStoreCSVUnknownColumn         domi18n.MessageID = "host.store.csv_unknown_column"                   // CSV 表头包含未知列
	KeyHostStoreCSVColumnCountMismatch   domi18n.MessageID = "host.store.csv_column_count_mismatch"            // CSV 数据行列数不匹配
	KeyHostStoreCSVRowInvalidField       domi18n.MessageID = "host.store.csv_row_invalid_field"                // CSV 数据行指定字段非法
	KeyHostStoreCSVInvalidPort           domi18n.MessageID = "host.store.csv_invalid_port"                     // CSV 端口超出 1..65535 范围
	KeyHostStoreCSVCertRequiresKey       domi18n.MessageID = "host.store.csv_cert_requires_key"                // CSV 配置 cert_path 时缺少 key_path
	KeyHostStoreOpenSSHNoNodes           domi18n.MessageID = "host.store.openssh_no_nodes"                     // OpenSSH 流未解析出可导入节点
	KeyHostStoreRevisionOverflow         domi18n.MessageID = "host.store.revision_overflow"                    // 配置修订号达到 uint64 上限
	KeyHostStoreWALGenerationCorrupt     domi18n.MessageID = "host.store.wal_generation_corrupt"               // 指定世代 WAL 已损坏
	KeyHostStoreWALEmpty                 domi18n.MessageID = "host.store.wal_empty"                            // 指定世代 WAL 文件为空
	KeyHostStoreWALTruncatedLine         domi18n.MessageID = "host.store.wal_truncated_line"                   // WAL 行缺少尾随换行符疑似截断
	KeyHostStoreWALLineError             domi18n.MessageID = "host.store.wal_line_error"                       // WAL 指定行解码错误
	KeyHostStoreWALMarshalFailed         domi18n.MessageID = "host.store.wal_marshal_failed"                   // 序列化规范 WAL 记录失败
	KeyHostStoreWALInvalidFrame          domi18n.MessageID = "host.store.wal_invalid_frame"                    // WAL 帧头或 CRC32 格式非法
	KeyHostStoreWALCRCMismatch           domi18n.MessageID = "host.store.wal_crc_mismatch"                     // WAL 帧 CRC32 校验和不匹配
	KeyHostStoreWALPayloadFailed         domi18n.MessageID = "host.store.wal_payload_failed"                   // WAL 载荷反序列化、摘要或归属校验失败
	KeyHostStoreImportWarnAlias          domi18n.MessageID = "host.store.import_warn.alias_skipped"            // OpenSSH 导入告警：别名不满足 NodeID 规则已跳过
	KeyHostStoreImportWarnHost           domi18n.MessageID = "host.store.import_warn.host_unresolved"          // OpenSSH 导入告警：缺少有效 HostName 已跳过
	KeyHostStoreImportWarnUser           domi18n.MessageID = "host.store.import_warn.user_missing"             // OpenSSH 导入告警：缺少用户名已跳过
	KeyHostStoreImportWarnCertNoKey      domi18n.MessageID = "host.store.import_warn.cert_without_key_skipped" // OpenSSH 导入告警：无可用私钥已跳过证书
	KeyHostStoreImportWarnDirective      domi18n.MessageID = "host.store.import_warn.unsupported_directive"    // OpenSSH 导入告警：直接导入已跳过不受支持指令

	// YAML vNext 编解码器错误键（internal/host/store/yamlcodec，20 个）。
	KeyHostYAMLUnsupportedSchema        domi18n.MessageID = "host.yaml.unsupported_schema_version"  // yamlcodec 不受支持 schema 版本（哨兵）
	KeyHostYAMLSectionKey               domi18n.MessageID = "host.yaml.section_key"                 // 配置节与键路径前缀
	KeyHostYAMLEmptyConfig              domi18n.MessageID = "host.yaml.empty_config"                // YAML 配置文件为空
	KeyHostYAMLDecodeFailed             domi18n.MessageID = "host.yaml.decode_failed"               // YAML vNext 解码失败
	KeyHostYAMLInvalidVersion           domi18n.MessageID = "host.yaml.invalid_version"             // schema 版本非 version: 2
	KeyHostYAMLMultipleDocs             domi18n.MessageID = "host.yaml.multiple_docs"               // 禁止多份或非法尾随 YAML 文档
	KeyHostYAMLNodeOverrideInvalid      domi18n.MessageID = "host.yaml.node_override_invalid"       // node_overrides 规则形态或字段值非法
	KeyHostYAMLDuplicateField           domi18n.MessageID = "host.yaml.duplicate_field"             // 配置映射包含重复字段
	KeyHostYAMLUnknownField             domi18n.MessageID = "host.yaml.unknown_field"               // 配置映射包含未知字段
	KeyHostYAMLNodeOverrideFieldInvalid domi18n.MessageID = "host.yaml.node_override_field_invalid" // node_overrides 指定字段值无效
	KeyHostYAMLInvalidFieldValue        domi18n.MessageID = "host.yaml.invalid_field_value"         // 指定配置字段取值非法
	KeyHostYAMLVaultStoreInvalid        domi18n.MessageID = "host.yaml.vault_store_invalid"         // vault.stores 条目名或类型非法
	KeyHostYAMLVaultDefaultUndeclared   domi18n.MessageID = "host.yaml.vault_default_undeclared"    // vault.default_store 未在 stores 中声明
	KeyHostYAMLPassphraseBindingPair    domi18n.MessageID = "host.yaml.passphrase_binding_pair"     // passphrase_ref 与 key_fingerprint 须成对
	KeyHostYAMLInvalidFieldCombo        domi18n.MessageID = "host.yaml.invalid_field_combo"         // 判别式变体字段组合非法
	KeyHostYAMLLiteralPathRequired      domi18n.MessageID = "host.yaml.literal_path_required"       // literal_path 要求有效字面路径
	KeyHostYAMLAlgoMissingTokens        domi18n.MessageID = "host.yaml.algo_missing_tokens"         // 算法策略缺少 tokens
	KeyHostYAMLAlgoInvalidToken         domi18n.MessageID = "host.yaml.algo_invalid_token"          // 算法令牌含非法前缀、空白或逗号
	KeyHostYAMLPathItemInvalid          domi18n.MessageID = "host.yaml.path_item_invalid"           // state=set 路径项非法或含首尾空白
	KeyHostYAMLEnvPatternPrefix         domi18n.MessageID = "host.yaml.env_pattern_prefix"          // 环境变量过滤模式禁止携带 '-' 前缀

	// 本机系统基础设施、SSH Agent、DNS SSHFP 与 TUN/TAP 适配器错误键（internal/host/sys/**，27 个）。
	KeyHostSysOrphanedProcessGroup  domi18n.MessageID = "host.sys.orphaned_process_group"     // 孤儿进程组禁止挂起（哨兵）
	KeyHostSysInputCanceled         domi18n.MessageID = "host.sys.input_canceled"             // 终端输入读取随作用域取消（哨兵）
	KeyHostSysHostnameFailed        domi18n.MessageID = "host.sys.hostname_failed"            // 查询本机主机名失败
	KeyHostSysSyscallFailed         domi18n.MessageID = "host.sys.syscall_failed"             // 系统调用失败
	KeyHostSysTerminalStreamReq     domi18n.MessageID = "host.sys.terminal_stream_required"   // 交互式流终端缺少必需成员
	KeyHostSysTerminalSizeFailed    domi18n.MessageID = "host.sys.terminal_size_failed"       // 查询终端窗口尺寸失败
	KeyHostSysTerminalNonPosSize    domi18n.MessageID = "host.sys.terminal_non_positive_size" // Windows 控制台返回非正尺寸
	KeyHostSysTerminalRawModeFailed domi18n.MessageID = "host.sys.terminal_raw_mode_failed"   // 配置终端原始模式失败
	KeyHostSysCancelHandleFailed    domi18n.MessageID = "host.sys.cancel_handle_failed"       // 创建取消唤醒句柄或管道失败
	KeyHostAgentInvalidSignArgs     domi18n.MessageID = "host.agent.invalid_sign_args"        // 公钥指纹与签名算法均须有效
	KeyHostAgentDisabled            domi18n.MessageID = "host.agent.disabled"                 // SSH Agent 已被显式禁用
	KeyHostAgentEnvUnset            domi18n.MessageID = "host.agent.env_unset"                // SSH Agent 环境变量未配置
	KeyHostAgentKeyNotFound         domi18n.MessageID = "host.agent.key_not_found"            // SSH Agent 中未找到指定指纹公钥
	KeyHostSSHFPDNSRcode            domi18n.MessageID = "host.sshfp.dns_rcode"                // DNS 服务器返回非零 RCODE
	KeyHostSSHFPNoServers           domi18n.MessageID = "host.sshfp.no_servers"               // 未配置或未发现可用 DNS 服务器
	KeyHostSSHFPInvalidServerAddr   domi18n.MessageID = "host.sshfp.invalid_server_addr"      // DNS 服务器地址非法
	KeyHostSSHFPWinAdaptersFailed   domi18n.MessageID = "host.sshfp.win_adapters_failed"      // 查询 Windows 网卡 DNS 列表失败
	KeyHostSSHFPInvalidDNSName      domi18n.MessageID = "host.sshfp.invalid_dns_name"         // DNS 查询域名或标签长度非法
	KeyHostSSHFPDNSHeaderMismatch   domi18n.MessageID = "host.sshfp.dns_header_mismatch"      // DNS 应答事务 ID 或 QR 标志不匹配
	KeyHostSSHFPDNSBadQDCount       domi18n.MessageID = "host.sshfp.dns_bad_qdcount"          // DNS 应答 QDCOUNT 不等于 1
	KeyHostSSHFPDNSQuestionMismatch domi18n.MessageID = "host.sshfp.dns_question_mismatch"    // DNS Question 段与查询不匹配
	KeyHostSSHFPDNSWireMalformed    domi18n.MessageID = "host.sshfp.dns_wire_malformed"       // DNS 线缆报文格式损坏或截断
	KeyHostSSHFPCNAMELoop           domi18n.MessageID = "host.sshfp.cname_loop"               // DNS CNAME 链存在环路
	KeyHostSSHFPCNAMETooDeep        domi18n.MessageID = "host.sshfp.cname_too_deep"           // DNS CNAME 链跳数超限
	KeyHostTUNDarwinL3Only          domi18n.MessageID = "host.tun.darwin_l3_only"             // macOS utun 仅支持 L3 点对点隧道
	KeyHostTUNPlatformUnsupported   domi18n.MessageID = "host.tun.platform_unsupported"       // 当前平台不支持原生 TUN/TAP 设备
	KeyHostTUNInvalidIPVersion      domi18n.MessageID = "host.tun.invalid_ip_version"         // utun L3 帧首字节 IP 版本无效

	// 凭据库路由、助手、钥匙串、离线库与 D-Bus Secret Service 错误键（internal/host/vault/**，29 个）。
	KeyHostVaultRouterEmpty           domi18n.MessageID = "host.vault.router_empty"               // RouterVault 未配置后端或默认存储
	KeyHostVaultRouterInvalidStore    domi18n.MessageID = "host.vault.router_invalid_store"       // 凭据存储名或后端实现无效
	KeyHostVaultStoreNotRegistered    domi18n.MessageID = "host.vault.store_not_registered"       // 凭据存储未注册
	KeyHostVaultHelperProtocol        domi18n.MessageID = "host.vault.helper_protocol"            // 外部助手协议帧非法（哨兵）
	KeyHostVaultHelperReadOnly        domi18n.MessageID = "host.vault.helper_read_only"           // 外部凭据助手处于只读模式
	KeyHostVaultHelperNonZeroExit     domi18n.MessageID = "host.vault.helper_non_zero_exit"       // 外部凭据助手返回非零退出状态
	KeyHostVaultHelperBase64Failed    domi18n.MessageID = "host.vault.helper_base64_failed"       // 助手返回凭据载荷 Base64 解码失败
	KeyHostVaultHelperBadResponse     domi18n.MessageID = "host.vault.helper_bad_response"        // 助手返回空响应、超限输出或非法 JSON
	KeyHostVaultKDFParamsInvalid      domi18n.MessageID = "host.vault.kdf_params_invalid"         // Argon2id 参数越界
	KeyHostVaultKDFSubprocessFailed   domi18n.MessageID = "host.vault.kdf_subprocess_failed"      // 隔离 KDF 子进程执行失败
	KeyHostVaultKeychainLoadFramework domi18n.MessageID = "host.vault.keychain_load_framework"    // 加载 macOS 系统框架失败
	KeyHostVaultKeychainResolveSymbol domi18n.MessageID = "host.vault.keychain_resolve_symbol"    // 解析 macOS Keychain 符号失败
	KeyHostVaultKeychainOSStatus      domi18n.MessageID = "host.vault.keychain_os_status"         // macOS Keychain 返回非零 OSStatus
	KeyHostVaultOfflineMetaDecode     domi18n.MessageID = "host.vault.offline_meta_decode"        // 解析离线凭据库元数据失败
	KeyHostVaultOfflineUnsupportedFmt domi18n.MessageID = "host.vault.offline_unsupported_format" // 不支持的离线库格式版本或 KDF
	KeyHostVaultOfflineItemDecode     domi18n.MessageID = "host.vault.offline_item_decode"        // 解析离线凭据条目失败
	KeyHostVaultOfflineCorruptField   domi18n.MessageID = "host.vault.offline_corrupt_field"      // 离线库元数据或条目字段损坏
	KeyHostVaultOfflineAEADFailed     domi18n.MessageID = "host.vault.offline_aead_failed"        // 离线凭据密文 AEAD 认证失败
	KeyHostVaultSSInvalidDHKey        domi18n.MessageID = "host.vault.ss_invalid_dh_key"          // Secret Service DH 服务端公钥非法
	KeyHostVaultSSInvalidCiphertext   domi18n.MessageID = "host.vault.ss_invalid_ciphertext"      // Secret Service AES-CBC 密文/IV/填充非法
	KeyHostVaultSSDBusInvalidAddr     domi18n.MessageID = "host.vault.ss_dbus_invalid_addr"       // D-Bus 会话地址格式非法
	KeyHostVaultSSDBusAbstractDenied  domi18n.MessageID = "host.vault.ss_dbus_abstract_denied"    // 安全策略拒绝 D-Bus 抽象套接字
	KeyHostVaultSSDBusUnknownParam    domi18n.MessageID = "host.vault.ss_dbus_unknown_param"      // 拒绝未知 D-Bus 地址参数
	KeyHostVaultSSEnvRequired         domi18n.MessageID = "host.vault.ss_env_required"            // 未显式指定 BusAddress 时缺少 EnvPort
	KeyHostVaultSSConnectFailed       domi18n.MessageID = "host.vault.ss_connect_failed"          // 校验或连接 D-Bus 会话总线失败
	KeyHostVaultSSHandshakeFailed     domi18n.MessageID = "host.vault.ss_handshake_failed"        // D-Bus Auth/Hello 握手失败
	KeyHostVaultSSBadDBusValue        domi18n.MessageID = "host.vault.ss_bad_dbus_value"          // D-Bus 响应成员值类型异常
	KeyHostVaultSSDBusCallFailed      domi18n.MessageID = "host.vault.ss_dbus_call_failed"        // Secret Service D-Bus 调用失败
	KeyHostVaultWinCredCallFailed     domi18n.MessageID = "host.vault.wincred_call_failed"        // Windows Credential Manager 调用失败
)
