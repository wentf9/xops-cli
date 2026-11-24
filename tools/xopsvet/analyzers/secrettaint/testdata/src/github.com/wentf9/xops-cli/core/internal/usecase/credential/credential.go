package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/host/vault"
	"gopkg.in/yaml.v3"
)

func okUseCasePassThrough(
	ctx context.Context,
	v ports.SecretVault,
	inter ports.InteractionPort,
) error {
	if err := inter.PromptSecret(ctx, "pass", func(box *secret.SecretBox) error {
		return v.PutAndVerify(ctx, "ref", box)
	}); err != nil {
		return err
	}
	return v.WithSecret(ctx, "ref", func(box *secret.SecretBox) error {
		_ = box.IsWiped()
		return v.PutAndVerify(ctx, "ref2", box)
	})
}

func badSinksAndWhitelist(
	ctx context.Context,
	v ports.SecretVault,
	sink ports.AuditSink,
	inter ports.InteractionPort,
) {
	_ = v.WithSecret(ctx, "ref", func(box *secret.SecretBox) error {
		slog.Any("k", box)         // want "禁止将 secret.SecretBox 传入日志汇点"
		_ = fmt.Errorf("%v", box)  // want "禁止将 secret.SecretBox 传入错误格式化汇点"
		_, _ = json.Marshal(box)   // want "禁止将 secret.SecretBox 传入序列化汇点"
		_, _ = yaml.Marshal(box)   // want "禁止将 secret.SecretBox 传入序列化汇点"
		events.Emit(box)           // want "禁止将 secret.SecretBox 传入事件/审计汇点"
		_ = sink.Append(ctx, box)  // want "禁止将 secret.SecretBox 传入事件/审计汇点"
		_ = inter.Notify(ctx, box) // want "禁止将 secret.SecretBox 传入事件/审计汇点"

		var erased any = box
		_, _ = json.Marshal(erased) // want "禁止将 secret.SecretBox 传入序列化汇点"

		_ = box.Use(func(plain []byte) error { // want "禁止在白名单.*调用或引用 SecretBox.Use"
			slog.Info("leak", "p", string(plain)) // want "禁止将明文机密.*传入日志汇点"
			return nil
		})
		useVal := box.Use // want "禁止在白名单.*调用或引用 SecretBox.Use"
		_ = useVal
		return nil
	})

	_ = vault.WithMasterKey(func(plain []byte) error { // want "禁止在白名单.*调用或引用 SecretBox.Use"
		_ = len(plain)
		return nil
	})
}
