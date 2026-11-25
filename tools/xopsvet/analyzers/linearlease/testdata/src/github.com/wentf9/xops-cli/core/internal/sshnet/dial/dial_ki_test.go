package dial

import (
	"context"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/crypto/ssh"
)

// okWhiteboxDialKI 验证包内白盒测试文件（package dial）同样遵守 P4-T1 窄模式，且逃逸仍严格拦截。
func okWhiteboxDialKI(ctx context.Context, vault ports.SecretVault, ref string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				answers[0] = string(plain)
				return nil
			})
		})
		return answers, nil
	})
}

func badWhiteboxDialKIOuterLeak(ctx context.Context, vault ports.SecretVault, ref string) ssh.AuthMethod {
	outer := make([]string, 1)
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				outer[0] = string(plain) // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
				return nil
			})
		})
		return outer, nil
	})
}
