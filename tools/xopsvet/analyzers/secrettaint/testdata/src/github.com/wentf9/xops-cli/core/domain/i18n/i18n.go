package i18n

type MessageID string
type Param struct{}
type Message struct{}

const KeySample MessageID = "sample.key"

func Str(k, v string) Param                                 { return Param{} }
func BoundStr(k, v string) Param                            { return Param{} }
func BoundDisplayText(raw string, maxBytes int) string      { return raw }
func Int(k string, v int) Param                             { return Param{} }
func NewMessage(id MessageID, params ...Param) Message      { return Message{} }
func E(id MessageID, params ...Param) error                 { return nil }
func Wrap(cause error, id MessageID, params ...Param) error { return cause }

// 对抗回归：即便误标 //xops:syncclosure，FormatTemplate 属于 SinkError，仍必须被汇点互斥防线拦截。
//
//xops:syncclosure
func FormatTemplate(tmpl string, resolve func(string) (string, bool)) string {
	if resolve == nil {
		return tmpl
	}
	v, _ := resolve("k")
	return v
}
