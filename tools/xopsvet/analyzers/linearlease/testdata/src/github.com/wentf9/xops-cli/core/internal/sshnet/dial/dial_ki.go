package dial

import (
	"context"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/crypto/ssh"
)

var (
	globalAnswers []string
	globalStr     string
	globalBytes   []byte
	globalBox     *secret.SecretBox
	globalAnsPtr  *[]string
)

type secretStr string

func escapeAnswersPtr(p *[]string) {
	globalAnsPtr = p // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
}

// okDialKI1Level 验证经典 1 层 box.Use 在带 //xops:borrowed 标注下合法写入局部 answers []string。
func okDialKI1Level(box *secret.SecretBox) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		err := box.Use(func(plain []byte) error {
			for i := range questions {
				answers[i] = string(plain)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return answers, nil
	})
}

// okDialKI2LevelWithSecret 验证 2 层 WithSecret -> box.Use 合法写入局部 answers []string。
func okDialKI2LevelWithSecret(ctx context.Context, vault ports.SecretVault, ref string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i := range questions {
			err := vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
				return box.Use(func(plain []byte) error {
					answers[i] = string(plain)
					return nil
				})
			})
			if err != nil {
				return nil, err
			}
		}
		return answers, nil
	})
}

// okDialKI2LevelPromptSecret 验证 2 层 PromptSecret -> box.Use 合法写入局部 answers []string。
func okDialKI2LevelPromptSecret(ctx context.Context, inter ports.InteractionPort) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i, q := range questions {
			err := inter.PromptSecret(ctx, q, func(box *secret.SecretBox) error {
				return box.Use(func(plain []byte) error {
					answers[i] = string(plain)
					return nil
				})
			})
			if err != nil {
				return nil, err
			}
		}
		return answers, nil
	})
}

// okDialKI2LevelCombinedNamedReturn 验证具名返回值 answers + 3 层嵌套同步闭包合法放行。
func okDialKI2LevelCombinedNamedReturn(ctx context.Context, vault ports.SecretVault, inter ports.InteractionPort, ref string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) (answers []string, err error) {
		answers = make([]string, len(questions))
		for i, q := range questions {
			if i == 0 {
				err = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
					return box.Use(func(plain []byte) error {
						func() {
							answers[i] = string(plain)
						}()
						return nil
					})
				})
			} else {
				err = inter.PromptSecret(ctx, q, func(box *secret.SecretBox) error {
					return box.Use(func(plain []byte) error {
						answers[i] = string(plain)
						return nil
					})
				})
			}
			if err != nil {
				return nil, err
			}
		}
		return answers, nil
	})
}

// badDialKIOuterSlice 验证写入 kiFn 外部声明与分配的 []string 切片必须拦截。
func badDialKIOuterSlice(ctx context.Context, vault ports.SecretVault, ref string) (ssh.AuthMethod, []string) {
	outer := make([]string, 1)
	m := ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				outer[0] = string(plain) // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
				return nil
			})
		})
		return outer, nil
	})
	return m, outer
}

// badDialKIOuterSliceReassignedInKI 验证外层 []string 变量即使在 kiFn 内重赋 make 也必须拦截。
func badDialKIOuterSliceReassignedInKI(ctx context.Context, vault ports.SecretVault, ref string) (ssh.AuthMethod, []string) {
	var outer []string
	m := ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		outer = make([]string, len(questions))
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				outer[0] = string(plain) // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
				return nil
			})
		})
		return outer, nil
	})
	return m, outer
}

// badDialKIGlobalSlice 验证写入全局 []string 切片必须拦截。
func badDialKIGlobalSlice(box *secret.SecretBox) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		globalAnswers = make([]string, len(questions))
		_ = box.Use(func(plain []byte) error {
			globalAnswers[0] = string(plain) // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
			return nil
		})
		return globalAnswers, nil
	})
}

// badDialKINonKIHelper 验证非 ssh.KeyboardInteractive 绑定的同名签名辅助函数必须拦截。
func badDialKINonKIHelper(name, instruction string, questions []string, echos []bool) ([]string, error) {
	answers := make([]string, len(questions))
	_ = secret.WithBytes([]byte("pw"), func(box *secret.SecretBox) error {
		return box.Use(func(plain []byte) error {
			answers[0] = string(plain) // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
			return nil
		})
	})
	return answers, nil
}

// badDialKINonExclusiveClosure 验证同时直接调用的非独占 KI 闭包必须拦截。
func badDialKINonExclusiveClosure(ctx context.Context, vault ports.SecretVault, ref string) ssh.AuthMethod {
	cb := func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				answers[0] = string(plain) // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
				return nil
			})
		})
		return answers, nil
	}
	_, _ = cb("", "", []string{"q"}, []bool{false})
	return ssh.KeyboardInteractive(cb)
}

// ExportedKIChallenge 验证对外导出的具名函数即使传入 ssh.KeyboardInteractive 也不得享受独占豁免。
func ExportedKIChallenge(name, instruction string, questions []string, echos []bool) ([]string, error) {
	answers := make([]string, len(questions))
	_ = secret.WithBytes([]byte("pw"), func(box *secret.SecretBox) error {
		return box.Use(func(plain []byte) error {
			answers[0] = string(plain) // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
			return nil
		})
	})
	return answers, nil
}

func badDialKIExportedFunc() ssh.AuthMethod {
	return ssh.KeyboardInteractive(ExportedKIChallenge)
}

// badDialKIRawBytesAndBoxEscape 验证 kiFn 内逃逸原始 plain []byte 或 *SecretBox 必须拦截。
func badDialKIRawBytesAndBoxEscape(ctx context.Context, vault ports.SecretVault, ref string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		rawSlices := make([][]byte, 1)
		boxes := make([]*secret.SecretBox, 1)
		answers := make([]string, len(questions))
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			boxes[0] = box  // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
			globalBox = box // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
			return box.Use(func(plain []byte) error {
				rawSlices[0] = plain // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
				globalBytes = plain  // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
				answers[0] = string(plain)
				return nil
			})
		})
		_ = rawSlices
		_ = boxes
		return answers, nil
	})
}

// badDialKIStringAndLocalAliasLeak 验证 string(plain) 写入外层变量及 box.Use 内局部 []string 别名逃逸必须拦截。
func badDialKIStringAndLocalAliasLeak(box *secret.SecretBox) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		_ = box.Use(func(plain []byte) error {
			s := string(plain)
			answers[0] = s
			globalStr = s // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
			local := make([]string, 1)
			local[0] = s
			globalAnswers = local // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
			return nil
		})
		return answers, nil
	})
}

// badDialKINamedStringType 验证自定义命名字符串切片（非精确内置 []string）不得享受豁免。
func badDialKINamedStringType(box *secret.SecretBox) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		custom := make([]secretStr, 1)
		_ = box.Use(func(plain []byte) error {
			custom[0] = secretStr(plain) // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
			return nil
		})
		_ = custom
		return nil, nil
	})
}

// badDialKI2LevelMutateAndEscapeCell 验证 2 层闭包改写 answers 为全局切片或逃逸 &answers 必须按 Fail-Closed 拦截。
func badDialKI2LevelMutateAndEscapeCell(ctx context.Context, vault ports.SecretVault, ref string) ssh.AuthMethod {
	_ = ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				answers = globalAnswers
				answers[0] = string(plain) // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
				return nil
			})
		})
		return answers, nil
	})
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				escapeAnswersPtr(&answers)
				answers[0] = string(plain) // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
				return nil
			})
		})
		return answers, nil
	})
}

// badDialKIOuterBoxCaptured 验证外层 WithSecret 借出的 box 严禁被非同步 ssh.KeyboardInteractive 闭包捕获。
func badDialKIOuterBoxCaptured(ctx context.Context, vault ports.SecretVault, ref string) ssh.AuthMethod {
	var m ssh.AuthMethod
	_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
		m = ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) { // want "禁止将捕获了 //xops:borrowed 变量的闭包传入非同步调用|禁止在非同步子闭包中捕获 //xops:borrowed 借用变量"
			answers := make([]string, len(questions))
			_ = box.Use(func(plain []byte) error {
				answers[0] = string(plain)
				return nil
			})
			return answers, nil
		})
		return nil
	})
	return m
}
