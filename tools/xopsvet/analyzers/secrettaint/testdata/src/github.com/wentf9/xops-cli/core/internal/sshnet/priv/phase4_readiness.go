package priv

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/crypto/ssh"
)

type privSecretErr string

func (e privSecretErr) Error() string { return string(e) }

type evilPrivWriter struct {
	stolen []byte
}

func (e *evilPrivWriter) Write(p []byte) (int, error) {
	e.stolen = append(e.stolen, p...)
	return len(p), nil
}

type privEscalator struct {
	stdin io.WriteCloser
}

func openPrivSessionStdin(sess *ssh.Session) (io.WriteCloser, error) {
	return sess.StdinPipe()
}

func openPrivRemoteSessionStdin(sess ports.RemoteSession) (io.WriteCloser, error) {
	return sess.StdinPipe()
}

type fakeRemoteSession interface {
	StdinPipe() (io.WriteCloser, error)
}

type fakeRemoteSessionImpl struct{}

func (*fakeRemoteSessionImpl) StdinPipe() (io.WriteCloser, error) {
	return nil, nil
}

func openFakeRemoteSessionStdin(sess fakeRemoteSession) (io.WriteCloser, error) {
	return sess.StdinPipe()
}

// okPrivRemoteSessionStdinPipe 验证 LayerCoreSSHNetPriv 放行 (ports.RemoteSession).StdinPipe
// （接口 invoke、同包辅助转发、io.Writer 装箱、Phi 合并及闭包内直接获取），以支持 dial 与 mux 统一提权握手。
func okPrivRemoteSessionStdinPipe(
	sess ports.RemoteSession,
	ch ssh.Channel,
	useRemote bool,
	passBox *secret.SecretBox,
) error {
	remoteStdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	helperRemoteStdin, err := openPrivRemoteSessionStdin(sess)
	if err != nil {
		return err
	}
	var boxedRemote io.Writer = remoteStdin
	var chosen io.Writer = ch
	if useRemote {
		chosen = remoteStdin
	}

	return passBox.Use(func(plain []byte) error {
		line := make([]byte, len(plain)+1)
		defer clear(line)
		copy(line, plain)
		line[len(plain)] = '\n'
		if _, wErr := remoteStdin.Write(line); wErr != nil {
			return wErr
		}
		if _, wErr := helperRemoteStdin.Write(line); wErr != nil {
			return wErr
		}
		if _, wErr := boxedRemote.Write(line); wErr != nil {
			return wErr
		}
		if _, wErr := chosen.Write(line); wErr != nil {
			return wErr
		}
		inlineStdin, sErr := sess.StdinPipe()
		if sErr != nil {
			return sErr
		}
		if _, wErr := inlineStdin.Write(line); wErr != nil {
			return wErr
		}
		return nil
	})
}

// okPrivEscalationWriters 验证 LayerCoreSSHNetPriv 严格正向白名单：
// 放行 (*ssh.Session).StdinPipe、(*ssh.Client).OpenChannel、(ssh.Conn).OpenChannel、(ssh.NewChannel).Accept、
// 静态类型 ssh.Channel 形参、同包辅助转发与 ssh.ParseRawPrivateKey* -> ssh.NewSignerFromKey/NewSignerFromSigner。
func okPrivEscalationWriters(
	sess *ssh.Session,
	cli *ssh.Client,
	conn ssh.Conn,
	newCh ssh.NewChannel,
	ch ssh.Channel,
	usePipe bool,
	keyBox, passBox *secret.SecretBox,
) (ssh.Signer, error) {
	stdinPipe, err := sess.StdinPipe()
	if err != nil {
		return nil, err
	}
	helperStdin, err := openPrivSessionStdin(sess)
	if err != nil {
		return nil, err
	}
	cliCh, _, err := cli.OpenChannel("session", nil)
	if err != nil {
		return nil, err
	}
	connCh, _, err := conn.OpenChannel("session", nil)
	if err != nil {
		return nil, err
	}
	accCh, _, err := newCh.Accept()
	if err != nil {
		return nil, err
	}
	var boxedCh io.Writer = ch
	var chosen io.Writer = ch
	if usePipe {
		chosen = stdinPipe
	}

	if err := passBox.Use(func(plain []byte) error {
		line := make([]byte, len(plain)+1)
		defer clear(line)
		copy(line, plain)
		line[len(plain)] = '\n'
		if _, wErr := stdinPipe.Write(line); wErr != nil {
			return wErr
		}
		if _, wErr := helperStdin.Write(line); wErr != nil {
			return wErr
		}
		if _, wErr := ch.Write(line); wErr != nil {
			return wErr
		}
		if _, wErr := boxedCh.Write(line); wErr != nil {
			return wErr
		}
		if _, wErr := cliCh.Write(line); wErr != nil {
			return wErr
		}
		if _, wErr := connCh.Write(line); wErr != nil {
			return wErr
		}
		if _, wErr := accCh.Write(line); wErr != nil {
			return wErr
		}
		if _, wErr := chosen.Write(line); wErr != nil {
			return wErr
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// 验证 ParseRawPrivateKey* 保污输出经 ssh.NewSignerFromKey / NewSignerFromSigner 净化后安全返回
	var out ssh.Signer
	err = keyBox.Use(func(keyBytes []byte) error {
		raw, rErr := ssh.ParseRawPrivateKey(keyBytes)
		if rErr != nil {
			return rErr
		}
		s, sErr := ssh.NewSignerFromKey(raw)
		if sErr != nil {
			return sErr
		}
		out = s
		if cs, ok := raw.(crypto.Signer); ok {
			s2, csErr := ssh.NewSignerFromSigner(cs)
			if csErr != nil {
				return csErr
			}
			out = s2
		}
		return passBox.Use(func(passBytes []byte) error {
			raw2, pErr := ssh.ParseRawPrivateKeyWithPassphrase(keyBytes, passBytes)
			if pErr != nil {
				return pErr
			}
			s3, kErr := ssh.NewSignerFromKey(raw2)
			if kErr != nil {
				return kErr
			}
			out = s3
			return nil
		})
	})
	return out, err
}

var (
	outerPrivLeak   []byte
	outerPrivRawKey any
	globalPrivWrite io.Writer
)

type localWriterHolder struct {
	w io.Writer
}

func makeEvilBufWriter() io.Writer {
	return &bytes.Buffer{}
}

// badPrivGenericParamBypass 验证通用 io.Writer / io.WriteCloser 形参不得绕过正向白名单（Bypass 1）。
func badPrivGenericParamBypass(w io.Writer, wc io.WriteCloser, box *secret.SecretBox) error {
	return box.Use(func(plain []byte) error {
		_, _ = w.Write(plain)  // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = wc.Write(plain) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		return nil
	})
}

// badPrivStructFieldBypasses 验证值结构体 *ssa.Field 与指针形参 *ssa.FieldAddr 均须 Fail-Closed 拦截（Bypass 2 & 3）。
func badPrivStructFieldBypasses(valHolder localWriterHolder, ptrHolder *privEscalator, box *secret.SecretBox) error {
	return box.Use(func(plain []byte) error {
		_, _ = valHolder.w.Write(plain)     // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = ptrHolder.stdin.Write(plain) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		return nil
	})
}

// badPrivEscalationViolations 验证 5 类对抗绕过、error 染毒、切片逃逸与原始私钥泄漏均严格 Fail-Closed。
func badPrivEscalationViolations(sess *ssh.Session, box *secret.SecretBox) error {
	stdin, _ := sess.StdinPipe()
	var outerBuf bytes.Buffer
	var boxedBuf io.Writer = &outerBuf
	var boxedEvil io.Writer = &evilPrivWriter{}
	var boxedStdout io.Writer = os.Stdout
	helperBufW := makeEvilBufWriter()
	multiW := io.MultiWriter(stdin, &outerBuf)
	holder := &localWriterHolder{w: &outerBuf}
	b64Enc := base64.NewEncoder(base64.StdEncoding, &outerBuf)
	hexEnc := hex.NewEncoder(&outerBuf)
	conn, _ := net.Dial("tcp", "127.0.0.1:9")
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()
	var boxedPipe io.Writer = pw

	if err := box.Use(func(plain []byte) error {
		// 1. 禁止全局/丢弃器/标准输出/本地缓冲/恶意 writer/多路复制器/局部结构体字段
		_, _ = io.Discard.Write(plain)      // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = globalPrivWrite.Write(plain) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = os.Stdout.Write(plain)       // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = boxedStdout.Write(plain)     // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = boxedBuf.Write(plain)        // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = boxedEvil.Write(plain)       // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = helperBufW.Write(plain)      // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = multiW.Write(plain)          // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = holder.w.Write(plain)        // want "禁止将明文机密传入未经授权的外部调用或未知汇点"

		// 2. 禁止外部编码器/网络写入器（Bypass 4）与 io.Pipe 隐蔽通道（Bypass 5）
		_, _ = b64Enc.Write(plain)    // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = hexEnc.Write(plain)    // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = conn.Write(plain)      // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = pw.Write(plain)        // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = boxedPipe.Write(plain) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"

		// 3. 禁止 ParseRawPrivateKey 原始私钥逃逸或打日志
		raw, _ := ssh.ParseRawPrivateKey(plain)
		outerPrivRawKey = raw               // want "禁止将明文机密逃逸至外层变量"
		slog.Info("priv-raw-key", "k", raw) // want "禁止将明文机密.*传入日志汇点"

		// 4. 禁止伴随合法通道写入时发生切片逃逸或日志泄露
		outerPrivLeak = plain                       // want "禁止将明文机密逃逸至外层变量"
		slog.Info("priv-after", "v", string(plain)) // want "禁止将明文机密.*传入日志汇点"

		// 5. 禁止将明文染毒至返回 error（fmt.Errorf / errors.New）
		if _, err := stdin.Write(plain); err != nil {
			_ = fmt.Errorf("sudo failed %s: %w", plain, err) // want "禁止将明文机密.*传入错误格式化汇点"
			return errors.New(string(plain))                 // want "禁止将明文机密.*传入错误格式化汇点"
		}
		return nil
	}); err != nil {
		return err
	}

	// 6. 禁止通过自定义 error 类型直接 return 返回明文机密
	return box.Use(func(plain []byte) error {
		if _, err := stdin.Write(plain); err != nil {
			return privSecretErr(plain) // want "禁止通过 return 返回明文机密"
		}
		return nil
	})
}

// badPrivRemoteSessionViolations 验证针对 RemoteSession.StdinPipe 的对抗绕过：
// 伪造本地接口/结构体、混合 Phi、结构体字段中转、MultiWriter、切片逃逸及 error 染毒均须严格 Fail-Closed 拦截。
func badPrivRemoteSessionViolations(
	sess ports.RemoteSession,
	fake fakeRemoteSession,
	impl *fakeRemoteSessionImpl,
	useFake bool,
	box *secret.SecretBox,
) error {
	remoteStdin, _ := sess.StdinPipe()
	fakeStdin, _ := fake.StdinPipe()
	helperFakeStdin, _ := openFakeRemoteSessionStdin(fake)
	implStdin, _ := impl.StdinPipe()
	var mixed io.Writer = remoteStdin
	if useFake {
		mixed = fakeStdin
	}
	var outerBuf bytes.Buffer
	multiW := io.MultiWriter(remoteStdin, &outerBuf)
	holder := &privEscalator{stdin: remoteStdin}

	if err := box.Use(func(plain []byte) error {
		_, _ = fakeStdin.Write(plain)       // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = helperFakeStdin.Write(plain) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = implStdin.Write(plain)       // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = mixed.Write(plain)           // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = multiW.Write(plain)          // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_, _ = holder.stdin.Write(plain)    // want "禁止将明文机密传入未经授权的外部调用或未知汇点"

		outerPrivLeak = plain // want "禁止将明文机密逃逸至外层变量"

		if _, err := remoteStdin.Write(plain); err != nil {
			_ = fmt.Errorf("remote sudo failed %s: %w", plain, err) // want "禁止将明文机密.*传入错误格式化汇点"
			return errors.New(string(plain))                        // want "禁止将明文机密.*传入错误格式化汇点"
		}
		return nil
	}); err != nil {
		return err
	}

	return box.Use(func(plain []byte) error {
		if _, err := remoteStdin.Write(plain); err != nil {
			return privSecretErr(plain) // want "禁止通过 return 返回明文机密"
		}
		return nil
	})
}
