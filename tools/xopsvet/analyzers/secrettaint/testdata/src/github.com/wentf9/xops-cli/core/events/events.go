package events

import "github.com/wentf9/xops-cli/core/domain/secret"

type SessionEvent struct {
	ID  string
	Box *secret.SecretBox // want "禁止 secret.SecretBox 进入 Event/Audit/Plan/Error/序列化结构体字段"
}

type AuditEntry struct {
	Raw secret.SecretBox `json:"-"` // want "禁止 secret.SecretBox 进入 Event/Audit/Plan/Error/序列化结构体字段"
}

type EventBoxes []*secret.SecretBox // want "禁止 secret.SecretBox 进入 Event/Audit/Plan/Error/受限类型"

type EventAlias = *secret.SecretBox // want "禁止 secret.SecretBox 进入 Event/Audit/Plan/Error/受限类型"

type EventAnySlice []any

type Envelope struct {
	Payload any
}

func Emit(ev any) {}

func UnannotatedConsumer([]byte) error { return nil }

func badCompositeAny(box *secret.SecretBox) {
	_ = Envelope{Payload: box}                         // want "禁止将 secret.SecretBox 存入 Event/Audit/Plan/Error/序列化结构体字段"
	_ = EventAnySlice{box}                             // want "禁止将 secret.SecretBox 存入 Event/Audit/Plan/Error/序列化结构体字段"
	_ = Envelope{Payload: func() any { return box }()} // want "禁止将 secret.SecretBox 存入 Event/Audit/Plan/Error/序列化结构体字段"
}
