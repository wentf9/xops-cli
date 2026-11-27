package i18n

import domi18n "github.com/wentf9/xops-cli/core/domain/i18n"

type Localizer struct{}

func E(id domi18n.MessageID, params ...domi18n.Param) error               { return nil }
func (*Localizer) T(id domi18n.MessageID, params ...domi18n.Param) string { return "" }
func (*Localizer) Render(msg domi18n.Message) string                      { return "" }
func (*Localizer) RenderError(err error) string                           { return "" }
