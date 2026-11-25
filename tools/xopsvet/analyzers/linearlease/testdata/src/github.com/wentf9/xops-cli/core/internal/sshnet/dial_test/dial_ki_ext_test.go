package dial_test

import (
	"context"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/crypto/ssh"
)

// badExtTestDialKI 验证外置 dial_test 包剥夺 P4-T1 窄钩子特权，必须拦截 answers[0] = string(plain)。
func badExtTestDialKI(ctx context.Context, vault ports.SecretVault, ref string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				answers[0] = string(plain) // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
				return nil
			})
		})
		return answers, nil
	})
}
