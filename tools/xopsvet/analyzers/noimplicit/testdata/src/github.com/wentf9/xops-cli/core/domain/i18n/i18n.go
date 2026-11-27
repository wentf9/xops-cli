package i18n

type MessageID string

const KeyCoreErr MessageID = "core.err"

func Sentinel(id MessageID) error                        { return nil }
func SentinelWithFallback(id MessageID, fb string) error { return nil }

var ErrCore = Sentinel(KeyCoreErr)
var ErrCoreFallback = SentinelWithFallback(KeyCoreErr, "core fallback")
