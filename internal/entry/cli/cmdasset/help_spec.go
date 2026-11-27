package cmdasset

import (
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// HostsHelpText 返回 `xops hosts` 的双语帮助文档文本。
func HostsHelpText(loc *i18n.Localizer) string {
	return clikit.EnsureLocalizer(loc).T(i18n.KeyCLIHelpHosts)
}

// VaultHelpText 返回 `xops creds` / `xops vault` 的双语帮助文档文本。
func VaultHelpText(loc *i18n.Localizer) string {
	return clikit.EnsureLocalizer(loc).T(i18n.KeyCLIHelpVault)
}

// ConfigHelpText 返回 `xops config` 的双语帮助文档文本。
func ConfigHelpText(loc *i18n.Localizer) string {
	return clikit.EnsureLocalizer(loc).T(i18n.KeyCLIHelpConfig)
}
