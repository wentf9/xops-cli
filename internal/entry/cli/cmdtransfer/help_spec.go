package cmdtransfer

import (
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// SCPHelpText 返回 `xops scp` 的双语帮助文档文本。
func SCPHelpText(loc *i18n.Localizer) string {
	return clikit.EnsureLocalizer(loc).T(i18n.KeyCLIHelpSCP)
}

// SFTPHelpText 返回 `xops sftp` 的双语帮助文档文本。
func SFTPHelpText(loc *i18n.Localizer) string {
	return clikit.EnsureLocalizer(loc).T(i18n.KeyCLIHelpSFTP)
}
