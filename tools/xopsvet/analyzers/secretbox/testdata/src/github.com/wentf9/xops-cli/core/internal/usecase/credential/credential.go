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

func stealGeneric[T any](x T) T { return x }

var (
	_                = fmt.Sprint(&secret.SecretBox{}) // want "禁止将 secret.SecretBox 传入错误格式化汇点"
	pkgErasedBox any = &secret.SecretBox{}             // want "禁止将 secret.SecretBox 擦除为接口"
	_, _             = json.Marshal(pkgErasedBox)      // want "禁止将 secret.SecretBox 传入序列化汇点"
)

func badSinksErasureAndWhitelist(
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

		// v2.3.3 CRIT-2 / N2: 匿名结构体嵌入与 any 泛型擦除全封死
		_ = struct {
			*secret.SecretBox // want "禁止在命名或匿名结构体中嵌入 secret.SecretBox"
		}{box}
		_ = stealGeneric(box) // want "禁止将 secret.SecretBox 擦除为接口或作为泛型类型实参传递"

		var erased any = box
		_, _ = json.Marshal(erased) // want "禁止将 secret.SecretBox 传入序列化汇点" "禁止将 secret.SecretBox 擦除为接口"

		if strBox, ok := erased.(fmt.Stringer); ok {
			slog.Info("comma-ok-ta", "v", strBox) // want "禁止将 secret.SecretBox 传入日志汇点"
		}
		boxMap := map[string]any{"k": box} // want "禁止将 secret.SecretBox 擦除为接口"
		if mv, ok := boxMap["k"]; ok {
			slog.Info("comma-ok-map", "v", mv) // want "禁止将 secret.SecretBox 传入日志汇点"
		}

		safeMap := map[string]any{"k": "ok"}
		if sv, ok := safeMap["k"]; ok {
			slog.Info("clean-map", "v", sv)
		}

		_ = box.Use(func(plain []byte) error { // want "禁止在白名单.*调用或引用 SecretBox.Use"
			_ = len(plain)
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
