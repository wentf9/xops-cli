// Package cli 实现 XOps v2 完整极薄 CLI 入站驱动适配器（ADR-001 / ADR-010 / ADR-011 / Plan P5-T1）。
//
// 包结构采用按命令族正交拆分的子包布局，保证每个子包生产代码体量远低于 3,000 LOC 红线：
//   - internal/entry/cli/clikit      共享命令行底座（具名能力接口、作用域引擎会话、JSON/v2 编码、通用选项解析）；
//   - internal/entry/cli/cmdssh      会话、单机/批量执行、端口/TUN 转发与多路复用命令族（ssh/exec/tunnel/mux）；
//   - internal/entry/cli/cmdtransfer 文件传输命令族（scp/sftp）；
//   - internal/entry/cli/cmdasset    资产清单、凭据库与统一配置导入命令族（hosts/creds/vault/config）；
//   - internal/entry/cli/cmdops      编排、健康诊断、审计与交互/协议子入口命令族（playbook/doctor/audit/mcp/tui）。
//
// 核心架构与安全不变量：
//   - 零业务逻辑、零 internal/host/** 导入、零 core/osfs 与 core/ports 导入、零 os.Exit 调用；
//   - 全部子入口（tui/sftpshell/mcp/muxdaemon）与宿主只读钩子（审计检索、受控文件读取、工作目录解析）
//     均通过 AppConfig 强类型可选回调显式注入，未注入时严格失败关闭；
//   - `xops version`、`--help` 与 `playbook validate` 严禁触发 Engine 初始化或触碰本地状态目录；
//   - 全包 0 init()、0 可变包级 var、0 裸 go 语句、0 //nolint: 豁免。
package cli

import (
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

// 编译期契约断言：确保 *engine.Engine 原生满足 CLI 入站层最小会话执行契约。
var _ SessionRunner = (*engine.Engine)(nil)

// 本包重导出的不可变结构化哨兵错误，与内部子包共享完全一致的错误标识。
var (
	// ErrInvalidConfig 表示构造 CLI App 时缺少必填依赖或参数非法。
	ErrInvalidConfig = clikit.ErrInvalidConfig
	// ErrAppNotInitialized 表示在 nil 或未初始化零值 App 上调用运行方法。
	ErrAppNotInitialized = clikit.ErrAppNotInitialized
	// ErrUsage 表示命令行子命令或参数语法非法。
	ErrUsage = clikit.ErrUsage
	// ErrNotConfigured 表示所请求的子入口或宿主只读钩子尚未由组合根注入。
	ErrNotConfigured = clikit.ErrNotConfigured
	// ErrUnsupportedRunner 表示注入的 EngineHandle.Runner 未实现当前子命令所需能力接口。
	ErrUnsupportedRunner = clikit.ErrUnsupportedRunner
)
