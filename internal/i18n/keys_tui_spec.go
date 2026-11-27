package i18n

import domi18n "github.com/wentf9/xops-cli/core/domain/i18n"

// 本文件声明 Bubble Tea v2 终端工作台（internal/entry/tui）的全部强类型 MessageID 常量。
// 哨兵、配置错误与可包装错误参数键在 internal/rootcatalog 登记规范英文兜底；纯视图、状态与帮助文案仅登记于 rootcatalog.AllKeys()。
const (
	// TUI 哨兵与运行期/配置错误键（规范英文兜底登记于 internal/rootcatalog）。
	KeyTUINilContext             domi18n.MessageID = "tui.err.nil_context"               // TUI 上下文为 nil（哨兵）
	KeyTUIInvalidConfig          domi18n.MessageID = "tui.err.invalid_config"            // TUI 配置无效（哨兵）
	KeyTUIInvalidEvent           domi18n.MessageID = "tui.err.invalid_event"             // 收到无效或不支持的事件变体（哨兵）
	KeyTUITerminalRestore        domi18n.MessageID = "tui.err.terminal_restore"          // 终端状态恢复失败（哨兵）
	KeyTUITakeoverDisabled       domi18n.MessageID = "tui.err.takeover_disabled"         // 未配置交互会话接管回调（哨兵）
	KeyTUIConfigNoSource         domi18n.MessageID = "tui.err.config_no_source"          // 数据源不能全部为空
	KeyTUIConfigInvalidView      domi18n.MessageID = "tui.err.config_invalid_view"       // 初始视图编号无效
	KeyTUIConfigOutOfBounds      domi18n.MessageID = "tui.err.config_out_of_bounds"      // 窗口尺寸、缓冲或采样参数越界
	KeyTUIConfigInvalidCLIOpts   domi18n.MessageID = "tui.err.config_invalid_cli_opts"   // CLIOptions 校验失败
	KeyTUIConfigNilOpStream      domi18n.MessageID = "tui.err.config_nil_op_stream"      // OperationStreams 元素为 nil
	KeyTUIConfigMetricsInterval  domi18n.MessageID = "tui.err.config_metrics_interval"   // MetricsInterval 非正时长
	KeyTUIConfigInvalidLogTarget domi18n.MessageID = "tui.err.config_invalid_log_target" // DefaultLogTarget 无效
	KeyTUIEventEmpty             domi18n.MessageID = "tui.err.event_empty"               // 事件为空或校验失败
	KeyTUIEventUnsupportedType   domi18n.MessageID = "tui.err.event_unsupported_type"    // 未支持的事件类型
	KeyTUINoHostForMetrics       domi18n.MessageID = "tui.err.no_host_for_metrics"       // 未选中指标流目标主机
	KeyTUINoHostForLogs          domi18n.MessageID = "tui.err.no_host_for_logs"          // 未选中日志流目标主机
	KeyTUINoHostForTakeover      domi18n.MessageID = "tui.err.no_host_for_takeover"      // 未选中交互会话目标主机
	KeyTUIActionQueueBusy        domi18n.MessageID = "tui.err.action_queue_busy"         // 异步动作队列已满
	KeyTUIInventoryErr           domi18n.MessageID = "tui.err.inventory"                 // 资产刷新错误包装前缀
	KeyTUIStreamErr              domi18n.MessageID = "tui.err.stream"                    // 远端指标/日志流错误包装前缀
	KeyTUITakeoverErr            domi18n.MessageID = "tui.err.takeover"                  // 交互会话接管错误包装前缀
	KeyTUIStreamKindMetrics      domi18n.MessageID = "tui.stream_kind.metrics"           // 流类型标签：指标（可嵌入错误参数）
	KeyTUIStreamKindLogs         domi18n.MessageID = "tui.stream_kind.logs"              // 流类型标签：日志（可嵌入错误参数）

	// TUI 界面布局、视图标签、安全横幅、帮助与状态消息键（纯展示类，仅存于 tui.yaml）。
	KeyTUIWindowTitle               domi18n.MessageID = "tui.window_title"                 // 终端窗口标题模板
	KeyTUIBrand                     domi18n.MessageID = "tui.brand"                        // 顶栏品牌标题
	KeyTUIViewHosts                 domi18n.MessageID = "tui.view.hosts"                   // 视图标签：主机
	KeyTUIViewMetrics               domi18n.MessageID = "tui.view.metrics"                 // 视图标签：指标
	KeyTUIViewLogs                  domi18n.MessageID = "tui.view.logs"                    // 视图标签：日志
	KeyTUIViewOperations            domi18n.MessageID = "tui.view.operations"              // 视图标签：操作
	KeyTUIViewHelp                  domi18n.MessageID = "tui.view.help"                    // 视图标签：帮助
	KeyTUIViewInvalid               domi18n.MessageID = "tui.view.invalid"                 // 无效视图占位提示
	KeyTUIHeaderMeta                domi18n.MessageID = "tui.header.meta"                  // 顶栏事件与流计数摘要
	KeyTUIBannerHalted              domi18n.MessageID = "tui.banner.halted"                // 安全门控熔断告警横幅
	KeyTUIBannerHaltedDefaultReason domi18n.MessageID = "tui.banner.halted_default_reason" // 门控熔断缺省原因
	KeyTUIBannerUnknownOutcome      domi18n.MessageID = "tui.banner.unknown_outcome"       // OutcomeUnknown 禁重试警示横幅
	KeyTUIFilterLabel               domi18n.MessageID = "tui.filter.label"                 // 过滤栏只读态模板
	KeyTUIFilterEditing             domi18n.MessageID = "tui.filter.editing"               // 过滤栏编辑态模板
	KeyTUIHostsTitle                domi18n.MessageID = "tui.hosts.title"                  // 主机清单分区标题
	KeyTUIHostsEmpty                domi18n.MessageID = "tui.hosts.empty"                  // 主机清单空列表提示
	KeyTUIStreamIdle                domi18n.MessageID = "tui.stream.idle"                  // 流状态标签：空闲
	KeyTUIStreamStreaming           domi18n.MessageID = "tui.stream.streaming"             // 流状态标签：流式传输中
	KeyTUIMetricsTitle              domi18n.MessageID = "tui.metrics.title"                // 指标视图分区标题
	KeyTUIMetricsEmpty              domi18n.MessageID = "tui.metrics.empty"                // 指标视图空采样提示
	KeyTUIMetricsFrameSummary       domi18n.MessageID = "tui.metrics.frame_summary"        // 主机指标帧核心概览行
	KeyTUIMetricsDisks              domi18n.MessageID = "tui.metrics.disks"                // 磁盘占用分节标题
	KeyTUIMetricsTopProcesses       domi18n.MessageID = "tui.metrics.top_processes"        // 热门进程分节标题
	KeyTUILogsTitle                 domi18n.MessageID = "tui.logs.title"                   // 日志视图分区标题
	KeyTUILogsEmpty                 domi18n.MessageID = "tui.logs.empty"                   // 日志视图空列表提示
	KeyTUILogsTruncated             domi18n.MessageID = "tui.logs.truncated"               // 日志行截断后缀标签
	KeyTUIOpsTitle                  domi18n.MessageID = "tui.ops.title"                    // 操作视图分区标题
	KeyTUIOpsEmpty                  domi18n.MessageID = "tui.ops.empty"                    // 操作视图空事件提示
	KeyTUIOpStatusRunning           domi18n.MessageID = "tui.ops.status.running"           // 操作状态：运行中
	KeyTUIOpStatusOK                domi18n.MessageID = "tui.ops.status.ok"                // 操作状态：成功
	KeyTUIOpStatusFailed            domi18n.MessageID = "tui.ops.status.failed"            // 操作状态：失败
	KeyTUIOpStatusUnknown           domi18n.MessageID = "tui.ops.status.unknown"           // 操作状态：未知终态
	KeyTUIHelpTitle                 domi18n.MessageID = "tui.help.title"                   // 帮助页标题
	KeyTUIHelpBody                  domi18n.MessageID = "tui.help.body"                    // 帮助页快捷键正文（含大写 L 切换语言）
	KeyTUIFooterErrPrefix           domi18n.MessageID = "tui.footer.err_prefix"            // 底栏错误状态前缀
	KeyTUIFooterHelp                domi18n.MessageID = "tui.footer.help"                  // 底栏快捷键提示（含 L 语言）
	KeyTUISortCPU                   domi18n.MessageID = "tui.sort.cpu"                     // 进程排序方式：CPU
	KeyTUISortMem                   domi18n.MessageID = "tui.sort.mem"                     // 进程排序方式：内存
	KeyTUILangNameEn                domi18n.MessageID = "tui.lang.en"                      // 语言显示名称：英文
	KeyTUILangNameZh                domi18n.MessageID = "tui.lang.zh"                      // 语言显示名称：简体中文
	KeyTUIStatusReady               domi18n.MessageID = "tui.status.ready"                 // 初始就绪状态
	KeyTUIStatusLanguageSwitched    domi18n.MessageID = "tui.status.language_switched"     // 语言热切换完成提示
	KeyTUIStatusMetricsUpdated      domi18n.MessageID = "tui.status.metrics_updated"       // 指标帧更新提示
	KeyTUIStatusGateHalted          domi18n.MessageID = "tui.status.gate_halted"           // 安全门控熔断状态提示
	KeyTUIStatusFilterMode          domi18n.MessageID = "tui.status.filter_mode"           // 进入过滤输入模式提示
	KeyTUIStatusFilterCleared       domi18n.MessageID = "tui.status.filter_cleared"        // 过滤条件已清除提示
	KeyTUIStatusFilterApplied       domi18n.MessageID = "tui.status.filter_applied"        // 过滤条件已应用提示
	KeyTUIStatusRefreshingInventory domi18n.MessageID = "tui.status.refreshing_inventory"  // 正在刷新资产快照提示
	KeyTUIStatusInventoryFailed     domi18n.MessageID = "tui.status.inventory_failed"      // 资产刷新失败提示
	KeyTUIStatusInventoryLoaded     domi18n.MessageID = "tui.status.inventory_loaded"      // 资产加载完成提示
	KeyTUIStatusStartingMetrics     domi18n.MessageID = "tui.status.starting_metrics"      // 正在启动指标流提示
	KeyTUIStatusStartingLogs        domi18n.MessageID = "tui.status.starting_logs"         // 正在启动日志流提示
	KeyTUIStatusStoppingStreams     domi18n.MessageID = "tui.status.stopping_streams"      // 正在停止活跃流提示
	KeyTUIStatusProcessSort         domi18n.MessageID = "tui.status.process_sort"          // 进程排序已切换提示
	KeyTUIStatusStreamErr           domi18n.MessageID = "tui.status.stream_err"            // 流因错误停止提示
	KeyTUIStatusStreamActive        domi18n.MessageID = "tui.status.stream_active"         // 流进入活跃态提示
	KeyTUIStatusStreamIdle          domi18n.MessageID = "tui.status.stream_idle"           // 流进入空闲态提示
	KeyTUIStatusTakeoverErr         domi18n.MessageID = "tui.status.takeover_err"          // 交互接管异常结束提示
	KeyTUIStatusTakeoverDone        domi18n.MessageID = "tui.status.takeover_done"         // 交互接管正常返回提示
)
