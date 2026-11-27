// Command xops 是 XOps v2 全仓唯一的外部组合根可执行入口（ADR-001 / ADR-008 / ADR-011）。
//
// 核心工程与安全不变量：
//   - 全包 0 init()、0 全局可变单例、0 裸 go 语句、0 行内 //nolint:；
//   - 构建元信息仅通过满足 noimplicit 六重门控的只读 //xops:buildvar 变量接收链接期
//     -X 'main.buildVersion/buildCommit/buildTime' 注入（未注入时回退 runtime/debug.ReadBuildInfo()），
//     并转换为显式值结构体 cli.BuildInfo 注入 internal/entry/cli；
//   - 按需装配全部真实宿主出站适配器（ScopedRootFS、OperatorReadFS、YAMLInventoryStore、WALJournalStore、
//     OpenSSH/CSV FormatImporter、OpenSSH ConfigSource、多后端 RouterVault、SystemClock/CryptoEntropy/
//     homeAwareEnv/SystemProcess/Terminal/Interaction/SSHAgent/TUNDevice/SSHFPLookup、Audit FileSink + FileReconciler），
//     绝不在 `xops version` 或 `--help` 路径下初始化 Engine 或触碰 `~/.xops`；
//   - MCP 模式物理隔离：严禁向 Engine 注入 OperatorReadFS 或本地交互终端，仅暴露 ScopedRootFS 并运行 MCPServer.Prepare(ctx)；
//   - 退出期严格遵循 Entry -> Engine/UseCases -> Pool -> Vault -> Store -> Audit -> Sys/Relay 逆序停机。
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/wentf9/xops-cli/internal/entry/cli"
)

func main() {
	os.Exit(runProcess(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func runProcess(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), shutdownSignals()...)
	defer stop()
	return runProcessWithContext(ctx, args, stdin, stdout, stderr)
}

func runProcessWithContext(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	buildInfo := currentBuildInfo()
	app, err := cli.NewApp(cli.AppConfig{
		BuildInfo: buildInfo,
		EngineFactory: func(callCtx context.Context, opts cli.EngineInitOptions) (cli.EngineHandle, error) {
			return wireEngine(callCtx, opts, stdin, stdout)
		},
		RunTUI:       runTUISubEntry,
		RunSFTPShell: runSFTPShellSubEntry,
		RunMCP: func(callCtx context.Context, req cli.MCPStartRequest) error {
			return runMCPSubEntry(callCtx, req, buildInfo)
		},
		RunMuxDaemon:     runMuxDaemonSubEntry,
		ReadAuditLog:     readAuditLogHook,
		ReadOperatorFile: readOperatorFileHook,
		ResolveWorkDir:   resolveWorkDir,
		Stdin:            stdin,
		Stdout:           stdout,
		Stderr:           stderr,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "xops: %v\n", err)
		return 1
	}
	return app.Run(ctx, args)
}
