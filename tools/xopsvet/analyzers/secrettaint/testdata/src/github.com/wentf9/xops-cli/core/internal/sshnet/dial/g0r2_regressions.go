package dial

import (
	"errors"
	"log/slog"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"golang.org/x/crypto/ssh"
)

// okKeyboardInteractive 验证 P4-T1 真实模式：唯一流向 ssh.KeyboardInteractive 的 challenge 闭包内
// 同步 box.Use 写入局部 answers []string 并在槽 0 返回（槽 1 error 不染毒，闭包体零泄漏）。
func okKeyboardInteractive(box *secret.SecretBox) ssh.AuthMethod {
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

// badKILogAnswers 验证 challenge 闭包内若将 answers 写入日志，外层复审必须拦截（B-4/ST-7）。
func badKILogAnswers(box *secret.SecretBox) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		_ = box.Use(func(plain []byte) error {
			answers[0] = string(plain)
			return nil
		})
		slog.Info("leak", "a", answers[0]) // want "禁止将明文机密.*传入日志汇点"
		return answers, nil
	})
}

type kiTaintedErr string

func (e kiTaintedErr) Error() string { return string(e) }

// badKITaintedError 验证 challenge 闭包槽 1（error）携带明文时必须拦截（ST-7）。
func badKITaintedError(box *secret.SecretBox) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		_ = box.Use(func(plain []byte) error {
			answers[0] = string(plain)
			return nil
		})
		if len(questions) > 1 {
			return answers, errors.New(answers[0]) // want "禁止将明文机密.*传入错误格式化汇点"
		}
		return answers, kiTaintedErr(answers[0]) // want "禁止通过 return 返回明文机密"
	})
}

// badFakeKIHelper 非 ssh.KeyboardInteractive 绑定的同名签名函数不得享受 P4-T1 豁免（ST-7）。
func badFakeKIHelper(box *secret.SecretBox) ([]string, error) {
	answers := make([]string, 1)
	_ = box.Use(func(plain []byte) error {
		answers[0] = string(plain) // want "禁止将明文机密存入结构体或非字节切片容器字面量"
		return nil
	})
	return answers, nil
}
