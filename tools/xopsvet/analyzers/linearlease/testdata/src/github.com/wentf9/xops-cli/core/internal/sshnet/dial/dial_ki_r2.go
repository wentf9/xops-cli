package dial

import (
	"context"
	"iter"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/crypto/ssh"
)

type kiErrStr string

func (e kiErrStr) Error() string { return string(e) }

//xops:syncclosure
//xops:borrowed
func withNonSecretBytes(fn func(buf []byte) error) error { // want withNonSecretBytes:"syncclosure,borrowed"
	return fn([]byte("borrowed-non-secret"))
}

//xops:syncclosure
//xops:borrowed
func withNonSecretString(fn func(s string) error) error { // want withNonSecretString:"syncclosure,borrowed"
	return fn("borrowed-non-secret-str")
}

func nonSyncSink(fn func()) {
	_ = fn
}

// okDialKIHolderStructArrayClean 验证 kiFn 局部结构体数组切片 holder.buf[:] 在零泄漏时合法放行。
func okDialKIHolderStructArrayClean(ctx context.Context, vault ports.SecretVault, ref string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		var holder struct{ buf [1]string }
		answers := holder.buf[:]
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				answers[0] = string(plain)
				return nil
			})
		})
		return answers, nil
	})
}

// badDialKIR2MiddleClosureLocalSlice 验证 #19(a)：中间层闭包自建切片 leaked 不得享受 kiFn 豁免。
func badDialKIR2MiddleClosureLocalSlice(ctx context.Context, vault ports.SecretVault, ref string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			leaked := make([]string, 1)
			_ = box.Use(func(plain []byte) error {
				leaked[0] = string(plain) // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
				return nil
			})
			globalAnswers = leaked // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
			return nil
		})
		return nil, nil
	})
}

// badDialKIR2NestedInitAliasLeak 验证 #19(b)：外层 var answers 在内层闭包初始化 answers = s 必须拦截。
func badDialKIR2NestedInitAliasLeak(ctx context.Context, vault ports.SecretVault, ref string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		var answers []string
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			s := make([]string, len(questions))
			answers = s
			_ = box.Use(func(plain []byte) error {
				answers[0] = string(plain) // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
				return nil
			})
			globalAnswers = s
			return nil
		})
		return answers, nil
	})
}

// badDialKIR2MixedPhiLocalAndKI 验证 #19(c)：混合 kiFn answers 与 box.Use 局部切片的 Phi 必须拦截并反染。
func badDialKIR2MixedPhiLocalAndKI(ctx context.Context, vault ports.SecretVault, ref string, cond bool) ssh.AuthMethod {
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
				target[0] = string(plain) // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
				globalAnswers = target    // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
				return nil
			})
		})
		return answers, nil
	})
}

// badDialKIR2IndirectOuterAlias 验证 #19 Major #2：外层变量重赋 make 后再别名给局部 answers 必须拦截。
func badDialKIR2IndirectOuterAlias(ctx context.Context, vault ports.SecretVault, ref string) (ssh.AuthMethod, []string) {
	var outer []string
	m := ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		outer = make([]string, len(questions))
		answers := outer
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				answers[0] = string(plain) // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
				return nil
			})
		})
		return answers, nil
	})
	return m, outer
}

// badDialKIR2HolderStructArrayLeak 验证 #26 Blocker #1：holder.buf[:] 复审必须同时追踪 holder，拦截经 holder 外泄。
func badDialKIR2HolderStructArrayLeak(ctx context.Context, vault ports.SecretVault, ref string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		var holder struct{ buf [1]string }
		answers := holder.buf[:]
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				answers[0] = string(plain)
				return nil
			})
		})
		globalStr = holder.buf[0]               // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
		return answers, kiErrStr(holder.buf[0]) // want "禁止通过 return 返回 //xops:borrowed 借用变量"
	})
}

// badDialKIR2NonSecretBorrowed 验证 #26 Blocker #2：非 //xops:secretuse 借用回调与显式 //xops:borrowed FuncLit 严禁进入 P4-T1 豁免。
func badDialKIR2NonSecretBorrowed() ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		_ = withNonSecretBytes(func(buf []byte) error {
			answers[0] = string(buf) // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
			return nil
		})
		_ = withNonSecretString(func(s string) error {
			answers[0] = s // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
			return nil
		})
		lit := func(
			//xops:borrowed
			s string,
		) {
			answers[0] = s // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
		}
		lit("x")
		return answers, nil
	})
}

// badDialKIR2ReusedCallbackAndIIFESecretMix 验证复用同一闭包跨 secret/non-secret 及 box.Use 内 IIFE 传入非机密借用均被阻断。
func badDialKIR2ReusedCallbackAndIIFESecretMix(ctx context.Context, vault ports.SecretVault, ref string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			cb := func(p []byte) error {
				answers[0] = string(p) // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
				return nil
			}
			_ = box.Use(cb)
			_ = withNonSecretBytes(cb)
			return withNonSecretString(func(nonSec string) error {
				return box.Use(func(plain []byte) error {
					func(s string) {
						answers[0] = s // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
					}(nonSec)
					_ = plain
					return nil
				})
			})
		})
		return answers, nil
	})
}

// badDialKIR2KIFuncReAuditLeaks 验证 #26 Blocker #2：linearlease 对称复审 kiFn，独立拦截全局/外层/channel/非同步闭包/中间层/槽 1 逃逸。
func badDialKIR2KIFuncReAuditLeaks(ctx context.Context, vault ports.SecretVault, ref string, ch chan string) (ssh.AuthMethod, string) {
	var outerStr string
	m := ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			err := box.Use(func(plain []byte) error {
				answers[0] = string(plain)
				return nil
			})
			globalStr = answers[0] // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
			return err
		})
		globalAnswers = answers // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
		globalStr = answers[0]  // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
		outerStr = answers[0]   // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
		ch <- answers[0]        // want "禁止将 //xops:borrowed 借用变量发送至 channel"
		nonSyncSink(func() {    // want "禁止在非同步子闭包中捕获 //xops:borrowed 借用变量"
			_ = answers[0]
		})
		return answers, kiErrStr(answers[0]) // want "禁止通过 return 返回 //xops:borrowed 借用变量"
	})
	return m, outerStr
}

// badDialKIR2NamedReturnSlot1Leak 验证具名返回值 (answers, err) 仅豁免槽 0，槽 1 具名错误（无论寄存器提升还是 defer 槽位）均必须拦截。
func badDialKIR2NamedReturnSlot1Leak(ctx context.Context, vault ports.SecretVault, ref string) ssh.AuthMethod {
	_ = ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) (answers []string, err error) {
		answers = make([]string, len(questions))
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				answers[0] = string(plain)
				return nil
			})
		})
		err = kiErrStr(answers[0])
		return // want "禁止通过 return 返回 //xops:borrowed 借用变量"
	})
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) (answers []string, err error) { // want "禁止通过 return 返回 //xops:borrowed 借用变量"
		defer func() {
			if err == nil {
				err = kiErrStr(answers[0]) // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
			}
		}()
		answers = make([]string, len(questions))
		_ = vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			return box.Use(func(plain []byte) error {
				answers[0] = string(plain)
				return nil
			})
		})
		return answers, nil // want "禁止通过 return 返回 //xops:borrowed 借用变量"
	})
}

type borrowedLease struct {
	id string
}

//xops:syncclosure
//xops:borrowed
//xops:secretuse
func withLeaseAndSecret(fn func(l *borrowedLease, plain []byte) error) error { // want withLeaseAndSecret:"syncclosure,borrowed"
	return fn(&borrowedLease{id: "lease-1"}, []byte("sec"))
}

//xops:syncclosure
//xops:borrowed
//xops:secretuse
type mixedLeaseSecretCB func(l *borrowedLease, plain []byte) error // want mixedLeaseSecretCB:"syncclosure,borrowed"

func runMixedLeaseSecretCB(cb mixedLeaseSecretCB) error {
	return cb(&borrowedLease{id: "lease-2"}, []byte("sec"))
}

func withSecretAndNonSecretCallbacks( // want withSecretAndNonSecretCallbacks:"syncclosure,borrowed"
	//xops:secretuse
	//xops:borrowed
	onSec func(plain []byte) error,
	//xops:borrowed
	onLease func(l *borrowedLease) error,
	//xops:borrowed
	onTok func(tok string) error,
) error {
	if err := onSec([]byte("sec")); err != nil {
		return err
	}
	if err := onLease(&borrowedLease{id: "lease-3"}); err != nil {
		return err
	}
	return onTok("tok-3")
}

//xops:syncclosure
//xops:borrowed
func withExplicitInnerSecret(fn func( // want withExplicitInnerSecret:"syncclosure,borrowed"
	label string,
	//xops:secretuse
	tok string,
) error) error {
	return fn("lbl", "sec-tok")
}

// badDialKIR3MixedParamAndMultiCallback 验证 #46 Major #1：
// 1) 混合参数回调（*borrowedLease + []byte）与命名回调类型仅放行明文 []byte 形参，严禁借用句柄字段逃逸；
// 2) 多回调仅对标注 //xops:secretuse 的 onSec 放行，严禁 onLease 句柄字段与 onTok string 形参逃逸；
// 3) 显式内层 //xops:secretuse 形参仅放行被标形参，严禁未标 string 形参逃逸；
// 4) 内联 IIFE 混传非机密借用与明文时按形参槽位严格隔离 SecretOnly。
func badDialKIR3MixedParamAndMultiCallback() ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		_ = withLeaseAndSecret(func(l *borrowedLease, plain []byte) error {
			answers[0] = string(plain)
			answers[1] = l.id // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
			func(a *borrowedLease, b []byte) {
				answers[0] = string(b)
				answers[1] = a.id // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
			}(l, plain)
			return nil
		})
		_ = runMixedLeaseSecretCB(func(l *borrowedLease, plain []byte) error {
			answers[0] = string(plain)
			answers[1] = l.id // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
			return nil
		})
		_ = withSecretAndNonSecretCallbacks(
			func(plain []byte) error {
				answers[0] = string(plain)
				return nil
			},
			func(l *borrowedLease) error {
				answers[0] = l.id // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
				return nil
			},
			func(tok string) error {
				answers[1] = tok // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
				return nil
			},
		)
		_ = withExplicitInnerSecret(func(label string, tok string) error {
			answers[0] = tok
			answers[1] = label // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
			return nil
		})
		return answers, nil
	})
}

//xops:syncclosure
//xops:borrowed
func withBorrowedIter(fn func(it iter.Seq[string]) error) error { // want withBorrowedIter:"syncclosure,borrowed"
	return fn(nil)
}

// badDialR4BotBorrowedIterMembership 验证 #58 Minor #2：两个不相交兄弟借用作用域汇入同一迭代器变量形成吸收底元 Bot 时，
// 成员判定仍必须识别为借用迭代器并拦截未知回调调用。
func badDialR4BotBorrowedIterMembership() {
	_ = withBorrowedIter(func(outerIt iter.Seq[string]) error {
		_ = outerIt
		var mixed iter.Seq[string]
		_ = withBorrowedIter(func(it1 iter.Seq[string]) error {
			mixed = it1 // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
			return nil
		})
		_ = withBorrowedIter(func(it2 iter.Seq[string]) error {
			mixed = it2 // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
			return nil
		})
		mixed(func(s string) bool { // want "禁止对非标准库或未知来源的借用迭代器执行回调调用"
			_ = s
			return false
		})
		return nil
	})
}
