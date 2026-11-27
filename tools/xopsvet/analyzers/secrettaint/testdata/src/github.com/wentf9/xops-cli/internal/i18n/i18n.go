package i18n

import domi18n "github.com/wentf9/xops-cli/core/domain/i18n"

type Localizer struct{}

func Str(k, v string) domi18n.Param                                       { return domi18n.Str(k, v) }
func BoundStr(k, v string) domi18n.Param                                  { return domi18n.BoundStr(k, v) }
func E(id domi18n.MessageID, params ...domi18n.Param) error               { return nil }
func (*Localizer) T(id domi18n.MessageID, params ...domi18n.Param) string { return "" }
func (*Localizer) Render(msg domi18n.Message) string                      { return "" }
func (*Localizer) RenderError(err error) string                           { return "" }
