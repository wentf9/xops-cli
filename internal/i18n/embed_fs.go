package i18n

import "embed"

//go:embed locales/*/*.yaml
var localeFiles embed.FS
