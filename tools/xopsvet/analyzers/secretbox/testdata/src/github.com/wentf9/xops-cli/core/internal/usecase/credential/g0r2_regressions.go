package credential

import (
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/internal/host/vault"
)

func badSecretUseFuncVal() {
	f := vault.WithMasterKey // want "禁止在白名单.*外调用或引用 SecretBox\\.Use / //xops:secretuse"
	_ = f
}

func badLocalTypes() {
	type localDTO struct {
		B *secret.SecretBox // want "禁止 secret\\.SecretBox 进入 Event/Audit/Plan/Error/序列化结构体字段"
	}
	_ = localDTO{}
	var anon struct {
		B *secret.SecretBox `json:"b"` // want "禁止 secret\\.SecretBox 进入带序列化标签的匿名结构体字段"
	}
	_ = anon
}
