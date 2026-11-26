package helper

import (
	"bytes"
	"context"
	"encoding/base64"
	"log/slog"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
)

func okHelperStdinOnly(ctx context.Context, proc ports.ProcessPort, spec ports.ProcessSpec, box *secret.SecretBox) error {
	return box.Use(func(plain []byte) error {
		b64 := base64.StdEncoding.EncodeToString(plain)
		payload := []byte(`{"secret":"` + b64 + `"}`)
		defer clear(payload)
		_, err := proc.Run(ctx, spec, bytes.NewReader(payload))
		return err
	})
}

func badHelperViolations(ctx context.Context, proc ports.ProcessPort, box *secret.SecretBox) {
	_ = box.Use(func(plain []byte) error {
		// 反例 1：严禁将明文放入 ProcessSpec（如 Command/Args/Env）
		badSpec := ports.ProcessSpec{Command: string(plain)} // want "禁止将明文机密存入结构体或非字节切片容器字面量"
		_, _ = proc.Run(ctx, badSpec, nil)                   // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		// 反例 2：严禁泄漏至日志
		slog.Info("helper-leak", "v", string(plain)) // want "禁止将明文机密.*传入日志汇点"
		return nil
	})
}
