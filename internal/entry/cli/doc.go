// Package cli 实现 XOps v2 极薄 CLI 入站驱动适配器（ADR-001 / ADR-011 / Plan P2.5-T2）。
//
// 核心架构与安全不变量：
//   - 零业务逻辑、零 internal/host/** 导入、零 core/osfs 与 core/ports 导入、零 os.Exit 调用；
//   - 仅依赖 core/{domain,events,engine,conc} 与 Go 标准库，所有 I/O 流与核心引擎按需构造工厂均通过
//     AppConfig 显式注入，保证命令解析、退出码映射与交互边界可 100% 进程内确定性单测；
//   - 构建元信息通过只读值结构体 BuildInfo 由组合根（cmd/xops）显式注入，xops version 与 --help
//     严禁触发 Engine 初始化或触碰本机状态目录；
//   - 全包 0 init()、0 可变包级 var、0 裸 go 语句、0 //nolint: 豁免。
package cli

import (
	"errors"

	"github.com/wentf9/xops-cli/core/engine"
)

// 编译期契约断言：确保 *engine.Engine 原生满足 CLI 入站层所需的最小会话执行接口。
var _ SessionRunner = (*engine.Engine)(nil)

// 本包导出的规范化哨兵错误，供调用方与测试精确区分配置、参数语法与运行期失败类别。
var (
	// ErrInvalidConfig 表示构造 CLI App 时缺少必填依赖或参数非法。
	ErrInvalidConfig = errors.New("cli: 无效的 AppConfig 配置")
	// ErrAppNotInitialized 表示在 nil 或未初始化零值 App 上调用运行方法。
	ErrAppNotInitialized = errors.New("cli: App 未初始化")
	// ErrUsage 表示命令行子命令或参数语法非法。
	ErrUsage = errors.New("cli: 命令行参数无效")
)

const (
	// exitCodeOK 表示命令成功退出。
	exitCodeOK = 0
	// exitCodeGeneralError 表示通用运行期错误或关闭阶段故障。
	exitCodeGeneralError = 1
	// exitCodeUsage 表示命令行子命令或选项参数语法错误。
	exitCodeUsage = 2
	// exitCodeSSHError 对齐 OpenSSH ssh(1) 约定，表示 SSH 连接、认证、启动前拒绝或未知终态错误。
	exitCodeSSHError = 255
	// exitCodeSignalBase 为 POSIX 信号终止退出码基址（128 + signal）。
	exitCodeSignalBase = 128
)
