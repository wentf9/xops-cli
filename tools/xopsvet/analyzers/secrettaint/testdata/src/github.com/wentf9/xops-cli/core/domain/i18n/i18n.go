package i18n

type MessageID string
type Param struct{}
type Message struct{}

const KeySample MessageID = "sample.key"

func Str(k, v string) Param                                 { return Param{} }
func Int(k string, v int) Param                             { return Param{} }
func NewMessage(id MessageID, params ...Param) Message      { return Message{} }
func E(id MessageID, params ...Param) error                 { return nil }
func Wrap(cause error, id MessageID, params ...Param) error { return cause }
