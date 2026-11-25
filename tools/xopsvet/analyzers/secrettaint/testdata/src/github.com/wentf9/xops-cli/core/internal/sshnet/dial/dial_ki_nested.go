package dial

import (
	"context"
	"errors"
	"log/slog"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/crypto/ssh"
)

var (
	globalKIAnswers []string
	globalKIStr     string
	globalKIPtr     *[]string
)

func escapeKIAnswersPtr(p *[]string) {
	globalKIPtr = p // want "禁止将明文机密逃逸至外层变量"
}

// okDialKI2LevelWithSecret 验证 2 层嵌套闭包（kiFn -> WithSecret -> box.Use）写入局部 answers []string 合法放行。
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

// okDialKI2LevelPromptSecret 验证 2 层嵌套闭包（kiFn -> PromptSecret -> box.Use）写入局部 answers []string 合法放行。
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

// okDialKI2LevelCombinedNamedReturn 验证具名返回值 answers 与 WithSecret/PromptSecret 混合分支 + 3 层嵌套同步闭包。
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

// badDialKI2LevelLogAnswers 验证 2 层闭包写入后在 kiFn 内记日志必须拦截。
func badDialKI2LevelLogAnswers(ctx context.Context, vault ports.SecretVault, ref string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				answers[0] = string(plain)
				return nil
			})
		})
		slog.Info("leak-2level", "a", answers[0]) // want "禁止将明文机密.*传入日志汇点"
		return answers, nil
	})
}

// badDialKI2LevelMiddleClosureLog 验证在中间层 WithSecret 闭包内日志泄漏 answers[0] 必须拦截。
func badDialKI2LevelMiddleClosureLog(ctx context.Context, vault ports.SecretVault, ref string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			err := box.Use(func(plain []byte) error {
				answers[0] = string(plain)
				return nil
			})
			slog.Info("leak-middle", "a", answers[0]) // want "禁止将明文机密.*传入日志汇点"
			return err
		})
		return answers, nil
	})
}

// badDialKI2LevelTaintedError 验证 2 层闭包写入后槽 1 error 携带明文必须拦截。
func badDialKI2LevelTaintedError(ctx context.Context, inter ports.InteractionPort) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		_ = inter.PromptSecret(ctx, "otp", func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				answers[0] = string(plain)
				return nil
			})
		})
		if len(questions) > 1 {
			return answers, errors.New(answers[0]) // want "禁止将明文机密.*传入错误格式化汇点"
		}
		return answers, kiTaintedErr(answers[0]) // want "禁止通过 return 返回明文机密"
	})
}

// badDialKI2LevelLeakGlobalAndOuter 验证 2 层闭包写入后 answers 逃逸至全局变量或外层局部变量必须拦截。
func badDialKI2LevelLeakGlobalAndOuter(ctx context.Context, vault ports.SecretVault, ref string) (ssh.AuthMethod, string) {
	var outerCopy string
	m := ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				answers[0] = string(plain)
				return nil
			})
		})
		globalKIStr = answers[0] // want "禁止将明文机密逃逸至外层变量"
		outerCopy = answers[0]   // want "禁止将明文机密逃逸至外层变量"
		return answers, nil
	})
	return m, outerCopy
}

// badDialKI2LevelOuterVarReassignedInKI 验证外层 []string 变量在 kiFn 内重赋 make 后写入仍须拦截。
func badDialKI2LevelOuterVarReassignedInKI(ctx context.Context, vault ports.SecretVault, ref string) (ssh.AuthMethod, []string) {
	var outerAnswers []string
	m := ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		outerAnswers = make([]string, len(questions))
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				outerAnswers[0] = string(plain) // want "禁止将明文机密存入结构体或非字节切片容器字面量"
				return nil
			})
		})
		return outerAnswers, nil
	})
	return m, outerAnswers
}

// badDialKI2LevelNonKIHelper 验证非 ssh.KeyboardInteractive 绑定的 2 层闭包不得享受豁免。
func badDialKI2LevelNonKIHelper(ctx context.Context, vault ports.SecretVault, ref string) ([]string, error) {
	answers := make([]string, 1)
	_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
		return box.Use(func(plain []byte) error {
			answers[0] = string(plain) // want "禁止将明文机密存入结构体或非字节切片容器字面量"
			return nil
		})
	})
	return answers, nil
}

// badDialKI2LevelNonExclusiveClosure 验证非独占（同时直接调用）的 KI 闭包不得享受豁免。
func badDialKI2LevelNonExclusiveClosure(ctx context.Context, vault ports.SecretVault, ref string) ssh.AuthMethod {
	cb := func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				answers[0] = string(plain) // want "禁止将明文机密存入结构体或非字节切片容器字面量"
				return nil
			})
		})
		return answers, nil
	}
	_, _ = cb("", "", []string{"q"}, []bool{false})
	return ssh.KeyboardInteractive(cb)
}

// badDialKI2LevelMutatingCellToOuter 验证 2 层闭包中改写捕获单元为全局切片时按 Fail-Closed 拦截。
func badDialKI2LevelMutatingCellToOuter(ctx context.Context, vault ports.SecretVault, ref string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				answers = globalKIAnswers
				answers[0] = string(plain) // want "禁止将明文机密存入结构体或非字节切片容器字面量"
				return nil
			})
		})
		return answers, nil
	})
}

// badDialKI2LevelEscapingCellAddr 验证 2 层闭包中逃逸捕获单元地址 &answers 时按 Fail-Closed 拦截。
func badDialKI2LevelEscapingCellAddr(ctx context.Context, vault ports.SecretVault, ref string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				escapeKIAnswersPtr(&answers)
				answers[0] = string(plain) // want "禁止将明文机密存入结构体或非字节切片容器字面量"
				return nil
			})
		})
		return answers, nil
	})
}

// badDialKIMiddleClosureLocalSlice 验证 #19(a)：中间层 WithSecret 闭包自建局部切片 leaked 不得享受 kiFn 豁免。
func badDialKIMiddleClosureLocalSlice(ctx context.Context, vault ports.SecretVault, ref string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			leaked := make([]string, 1)
			_ = box.Use(func(plain []byte) error {
				leaked[0] = string(plain) // want "禁止将明文机密存入结构体或非字节切片容器字面量"
				return nil
			})
			globalKIAnswers = leaked
			slog.Info("pw", "s", leaked[0])
			return nil
		})
		return nil, nil
	})
}

// badDialKINestedInitAliasLeak 验证 #19(b)：外层 var answers 在内层闭包初始化 answers = s 后借 s 泄漏必须拦截。
func badDialKINestedInitAliasLeak(ctx context.Context, vault ports.SecretVault, ref string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		var answers []string
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			s := make([]string, len(questions))
			answers = s
			_ = box.Use(func(plain []byte) error {
				answers[0] = string(plain) // want "禁止将明文机密存入结构体或非字节切片容器字面量"
				return nil
			})
			globalKIAnswers = s
			slog.Info("pw", "s", s[0])
			return nil
		})
		return answers, nil
	})
}

// badDialKIMixedPhiLocalAndKI 验证 #19(c)：混合 kiFn answers 与 box.Use 局部切片的 Phi 目标必须拦截。
func badDialKIMixedPhiLocalAndKI(ctx context.Context, vault ports.SecretVault, ref string, cond bool) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				var target []string
				if cond {
					target = answers
				} else {
					target = make([]string, 1)
				}
				target[0] = string(plain) // want "禁止将明文机密存入结构体或非字节切片容器字面量"
				globalKIAnswers = target  // want "禁止将明文机密逃逸至外层变量"
				return nil
			})
		})
		return answers, nil
	})
}

// badDialKIIndirectOuterContainerAlias 验证 #19 Major #2：外层变量重赋 make 后再别名给局部 answers 必须拦截。
func badDialKIIndirectOuterContainerAlias(ctx context.Context, vault ports.SecretVault, ref string) (ssh.AuthMethod, []string) {
	var outer []string
	m := ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		outer = make([]string, len(questions))
		answers := outer
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				answers[0] = string(plain) // want "禁止将明文机密存入结构体或非字节切片容器字面量"
				return nil
			})
		})
		return answers, nil
	})
	return m, outer
}

// badDialKIHolderStructArrayBacking 验证 #26 Blocker #1：kiFn 局部结构体数组切片 holder.buf[:] 必须连同 holder 入种复审。
func badDialKIHolderStructArrayBacking(ctx context.Context, vault ports.SecretVault, ref string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		var holder struct{ buf [1]string }
		answers := holder.buf[:]
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				answers[0] = string(plain)
				return nil
			})
		})
		slog.Info("leaked", "pw", holder.buf[0])  // want "禁止将明文机密.*传入日志汇点"
		globalKIStr = holder.buf[0]               // want "禁止将明文机密逃逸至外层变量"
		return answers, errors.New(holder.buf[0]) // want "禁止将明文机密.*传入错误格式化汇点"
	})
}

type dialBorrowedLease struct {
	id string
}

// withDialSecretAndLeaseCallbacks 验证多回调仅对标注 //xops:secretuse 的 onSec 槽位触发明文审计，不误伤 onLease。
func withDialSecretAndLeaseCallbacks(
	//xops:secretuse
	onSec func(plain []byte) error,
	//xops:borrowed
	onLease func(l *dialBorrowedLease, tok string) error,
) error {
	if err := onSec([]byte("sec")); err != nil {
		return err
	}
	return onLease(&dialBorrowedLease{id: "lease-1"}, "tok-1")
}

// badDialKIMultiCallbackSecretSlotLeak 验证多回调中 onSec 槽位经 answers[0] 外泄仍被 secrettaint 拦截，且 onLease 不误触发。
func badDialKIMultiCallbackSecretSlotLeak() ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		_ = withDialSecretAndLeaseCallbacks(
			func(plain []byte) error {
				answers[0] = string(plain)
				return nil
			},
			func(l *dialBorrowedLease, tok string) error {
				slog.Info("non-secret-lease-ok", "id", l.id, "tok", tok)
				return nil
			},
		)
		slog.Info("leak-sec-slot", "a", answers[0]) // want "禁止将明文机密.*传入日志汇点"
		return answers, nil
	})
}

func samePkgCallbackPlusExtra(
	//xops:secretuse
	onSec func(plain []byte) error,
	extra []byte,
) error {
	slog.Info("same-pkg-extra-leak", "e", string(extra)) // want "禁止将明文机密.*传入日志汇点"
	return onSec(nil)
}

func samePkgPartialDirect(
	unmarked []byte,
	//xops:secretuse
	sec []byte,
) {
	slog.Info("same-pkg-partial-leak", "u", string(unmarked)) // want "禁止将明文机密.*传入日志汇点"
	_ = sec
}

func samePkgPartialDirectRet(
	unmarked []byte,
	//xops:secretuse
	sec []byte,
) []byte {
	_ = sec
	return unmarked
}

//xops:secretuse
func withTwoPlainSecret(fn func(a, b []byte) error) error {
	return fn(nil, nil)
}

//xops:secretuse
func withCallbackAndExtraSecret(fn func(onSec func([]byte) error, extra []byte) error) error {
	return fn(func([]byte) error { return nil }, nil)
}

func passthroughBytes(b []byte) []byte {
	return b
}

// badDialR4PerSlotTrustGates 验证 #58 Major #1：同包/跨包回调+非机密实参、部分 DirectSecret 实参泄漏及跨包回调准入均严格 Fail-Closed。
func badDialR4PerSlotTrustGates(box *secret.SecretBox) {
	_ = box.Use(func(plain []byte) error {
		_ = samePkgCallbackPlusExtra(func([]byte) error { return nil }, plain)
		samePkgPartialDirect(plain, nil)
		leakedRet := samePkgPartialDirectRet(plain, nil)
		slog.Info("ret-mask-leak", "r", leakedRet) // want "禁止将明文机密.*传入日志汇点"

		_ = secret.CrossPkgCallbackOnly(func([]byte) error { return nil }, plain) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_ = secret.CrossPkgPartialDirect(plain, nil)                              // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_ = secret.CrossPkgPartialDirect(nil, plain)                              // 槽 1 显式受 //xops:secretuse 覆盖，合法放行
		return nil
	})
	_ = withTwoPlainSecret(secret.CrossPkgPartialDirect)        // want "禁止将未标注 //xops:secretuse 的跨包函数传入 SecretBox\\.Use"
	_ = withCallbackAndExtraSecret(secret.CrossPkgCallbackOnly) // want "禁止将未标注 //xops:secretuse 的跨包函数传入 SecretBox\\.Use"
	_ = withTwoPlainSecret(secret.CrossPkgWholeDirect)          // 全明文形参覆盖，合法放行
}

// badDialR4DisjointBotReturnMask 验证 #58 Minor #2：两个不相交兄弟 box.Use 区间汇入同一变量落入吸收底元 Bot 后，
// computeReturnMask 仍必须按 map 成员存在性回染返回值并拦截外泄。
func badDialR4DisjointBotReturnMask(outerBox, boxA, boxB *secret.SecretBox) {
	_ = outerBox.Use(func(outerPlain []byte) error {
		_ = outerPlain
		var merged []byte
		_ = boxA.Use(func(a []byte) error {
			merged = a // want "禁止将明文机密逃逸至外层变量"
			return nil
		})
		_ = boxB.Use(func(b []byte) error {
			merged = b // want "禁止将明文机密逃逸至外层变量"
			return nil
		})
		out := passthroughBytes(merged)
		slog.Info("bot-ret-leak", "o", out) // want "禁止将明文机密.*传入日志汇点"
		return nil
	})
}
