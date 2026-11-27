package cmdops

import (
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// PlaybookHelpText 按给定本地化器返回 `xops playbook` 的帮助文档文本。
func PlaybookHelpText(loc *i18n.Localizer) string {
	return clikit.EnsureLocalizer(loc).T(i18n.KeyCLIHelpPlaybook)
}

// DoctorHelpText 按给定本地化器返回 `xops doctor` 的帮助文档文本。
func DoctorHelpText(loc *i18n.Localizer) string {
	return clikit.EnsureLocalizer(loc).T(i18n.KeyCLIHelpDoctor)
}

// AuditHelpText 按给定本地化器返回 `xops audit` 的帮助文档文本。
func AuditHelpText(loc *i18n.Localizer) string {
	return clikit.EnsureLocalizer(loc).T(i18n.KeyCLIHelpAudit)
}

// TUIHelpText 按给定本地化器返回 `xops tui` 的帮助文档文本。
func TUIHelpText(loc *i18n.Localizer) string {
	return clikit.EnsureLocalizer(loc).T(i18n.KeyCLIHelpTUI)
}

// MCPHelpText 按给定本地化器返回 `xops mcp` 的帮助文档文本。
func MCPHelpText(loc *i18n.Localizer) string {
	return clikit.EnsureLocalizer(loc).T(i18n.KeyCLIHelpMCP)
}
