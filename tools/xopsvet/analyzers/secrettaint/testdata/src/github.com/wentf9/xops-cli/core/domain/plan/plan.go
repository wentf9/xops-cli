package plan

import "github.com/wentf9/xops-cli/core/domain/secret"

type ExecPlan struct {
	Secret *secret.SecretBox // want "禁止 secret.SecretBox 进入 Event/Audit/Plan/Error/序列化结构体字段"
}

type ValErr struct {
	Box secret.SecretBox // want "禁止 secret.SecretBox 进入 Event/Audit/Plan/Error/序列化结构体字段"
}

func (ValErr) Error() string { return "err" }

type PtrErr struct {
	Boxes []*secret.SecretBox // want "禁止 secret.SecretBox 进入 Event/Audit/Plan/Error/序列化结构体字段"
}

func (*PtrErr) Error() string { return "ptr" }

//xops:dto
type AnnotatedDTO struct {
	Inner struct { // want "禁止 secret.SecretBox 进入 Event/Audit/Plan/Error/序列化结构体字段"
		B *secret.SecretBox
	}
}

type TaggedStruct struct {
	Item *secret.SecretBox `yaml:"item"` // want "禁止 secret.SecretBox 进入 Event/Audit/Plan/Error/序列化结构体字段"
}

type NonStructErr []*secret.SecretBox // want "禁止 secret.SecretBox 进入 error 实现或 //xops:dto 类型"

func (NonStructErr) Error() string { return "slice-err" }

type PlanBox *secret.SecretBox // want "禁止 secret.SecretBox 进入 Event/Audit/Plan/Error/受限类型"
