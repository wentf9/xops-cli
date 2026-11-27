package cmdssh

import (
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// SSHHelpText 返回 `xops ssh` 的双语帮助文档文本。
func SSHHelpText(loc *i18n.Localizer) string {
	return clikit.EnsureLocalizer(loc).T(i18n.KeyCLIHelpSSH)
}

// ExecHelpText 返回 `xops exec` 的双语帮助文档文本。
func ExecHelpText(loc *i18n.Localizer) string {
	return clikit.EnsureLocalizer(loc).T(i18n.KeyCLIHelpExec)
}

// TunnelHelpText 返回 `xops tunnel` / `xops forward` 的双语帮助文档文本。
func TunnelHelpText(loc *i18n.Localizer) string {
	return clikit.EnsureLocalizer(loc).T(i18n.KeyCLIHelpTunnel)
}

// MuxHelpText 返回 `xops mux` 的双语帮助文档文本。
func MuxHelpText(loc *i18n.Localizer) string {
	return clikit.EnsureLocalizer(loc).T(i18n.KeyCLIHelpMux)
}
