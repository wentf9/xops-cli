package i18n

type MessageID string

type AliasMessageID = MessageID

const (
	MessageIDInvalid MessageID      = ""
	KeyCoreErr       MessageID      = "core.err"
	KeyAliasCore     AliasMessageID = "core.alias"
)

func Sentinel(id MessageID) error                        { return nil }
func SentinelWithFallback(id MessageID, fb string) error { return nil }

var ErrCore = Sentinel(KeyCoreErr)
var ErrCoreAlias = Sentinel(KeyAliasCore)
var ErrCoreFallback = SentinelWithFallback(KeyCoreErr, "core fallback") // want "禁止声明可变包级 var"
var ErrCoreInvalid = Sentinel(MessageIDInvalid)                         // want "禁止声明可变包级 var"
