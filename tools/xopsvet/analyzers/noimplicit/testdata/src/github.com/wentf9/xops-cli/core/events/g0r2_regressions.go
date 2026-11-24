package events

import "time"

// yamlOnlyDur 仅实现 MarshalYAML 未实现 JSON/Text 编码接口，在双协议 DTO 下不得放行（H2）。
type yamlOnlyDur struct {
	Raw time.Duration
}

func (yamlOnlyDur) MarshalYAML() (any, error) { return "1s", nil }

type BadYAMLOnlyDurationEvent struct {
	D yamlOnlyDur // want "禁止裸用 time.Duration"
}

// ptrTextDur 仅在指针接收者上实现 MarshalText；作为 map 值不可寻址，必须穿透拦截（M1）。
type ptrTextDur struct {
	Raw time.Duration
}

func (*ptrTextDur) MarshalText() ([]byte, error) { return []byte("1s"), nil }

type BadMapValuePtrTextEvent struct {
	ByHost map[string]ptrTextDur // want "禁止裸用 time.Duration"
}
