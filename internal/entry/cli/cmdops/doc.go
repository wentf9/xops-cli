// Package cmdops 实现 XOps v2 的自动化 Playbook、系统健康诊断、安全审计查询/对账及 TUI/MCP 子入口分发命令族
// （`playbook` / `doctor` / `audit` / `tui` / `mcp`）。
//
// 核心架构与安全不变量：
//   - 零业务逻辑、零 internal/host/** 导入、零 core/osfs 或 core/ports 导入、零 os.Exit；
//   - Playbook 文件经注入的 ReadOperatorFile 钩子或 stdin 读取，支持 YAML vNext v2 与 JSON，
//     统一收敛至 core/domain/playbook 的强校验 JSON/v2 解码器（零重复规则）；
//   - `audit list/tail/inspect` 与 `tui` / `mcp` 严格经 AppConfig 强类型回调注入，未注入时失败关闭；
//   - 全包 0 init()、0 可变包级 var、0 裸 go、0 //nolint:。
package cmdops

import (
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/i18n"
)

func requireAutomationClient(runner clikit.SessionRunner) (clikit.AutomationClient, error) {
	c, ok := runner.(clikit.AutomationClient)
	if !ok {
		return nil, i18n.EF(clikit.ErrUnsupportedRunner, i18n.KeyCLICapabilityRequired, i18n.Str("capability", "AutomationClient"))
	}
	return c, nil
}

func requireInventoryClient(runner clikit.SessionRunner) (clikit.InventoryClient, error) {
	c, ok := runner.(clikit.InventoryClient)
	if !ok {
		return nil, i18n.EF(clikit.ErrUnsupportedRunner, i18n.KeyCLICapabilityRequired, i18n.Str("capability", "InventoryClient"))
	}
	return c, nil
}

func requireVaultClient(runner clikit.SessionRunner) (clikit.VaultClient, error) {
	c, ok := runner.(clikit.VaultClient)
	if !ok {
		return nil, i18n.EF(clikit.ErrUnsupportedRunner, i18n.KeyCLICapabilityRequired, i18n.Str("capability", "VaultClient"))
	}
	return c, nil
}

func requireReconcileClient(runner clikit.SessionRunner) (clikit.ReconcileClient, error) {
	c, ok := runner.(clikit.ReconcileClient)
	if !ok {
		return nil, i18n.EF(clikit.ErrUnsupportedRunner, i18n.KeyCLICapabilityRequired, i18n.Str("capability", "ReconcileClient"))
	}
	return c, nil
}
