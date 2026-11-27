package i18n

import "embed"

//go:embed locales.txt
var testEmbed embed.FS // want "禁止声明可变包级 var"

func useTestEmbed() {
	_ = testEmbed
}
