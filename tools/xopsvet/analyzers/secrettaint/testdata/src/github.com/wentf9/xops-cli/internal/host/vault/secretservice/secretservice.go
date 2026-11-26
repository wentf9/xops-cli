package secretservice

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"log/slog"

	"github.com/ebitengine/purego"
	"github.com/godbus/dbus/v5"
	"github.com/wentf9/xops-cli/core/domain/secret"
)

type dbusSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

var (
	globalDBusSecret dbusSecret
	leakedCipherBuf  []byte
)

type fakeBlockMode struct{}

func (fakeBlockMode) BlockSize() int          { return 16 }
func (fakeBlockMode) CryptBlocks(dst, src []byte) {}

func okSecretServiceDHAndPlain(ctx context.Context, obj dbus.BusObject, concrete *dbus.Object, sess dbus.ObjectPath, aesKey, iv []byte, props map[string]dbus.Variant, box *secret.SecretBox) ([]byte, error) {
	var cipherOut []byte
	err := box.Use(func(plain []byte) error {
		// 1. 合法 DH AES-128-CBC 加密（仅在 vault/secretservice 放行）
		block, bErr := aes.NewCipher(aesKey)
		if bErr != nil {
			return bErr
		}
		mode := cipher.NewCBCEncrypter(block, iv)
		padded := make([]byte, len(plain))
		copy(padded, plain)
		defer clear(padded)
		ct := make([]byte, len(padded))
		mode.CryptBlocks(ct, padded)
		cipherOut = ct

		// 2. 合法 plain 回退（局部 dbusSecret.Value + 精确常量 D-Bus 方法）
		sec := dbusSecret{Session: sess, Value: plain, ContentType: "text/plain"}
		_ = obj.CallWithContext(ctx, "org.freedesktop.Secret.Collection.CreateItem", 0, props, sec, true)
		_ = concrete.Call("org.freedesktop.Secret.Item.SetSecret", 0, sec)
		return nil
	})
	return cipherOut, err
}

func badSecretServiceViolations(ctx context.Context, obj dbus.BusObject, dynMethod string, sess dbus.ObjectPath, aesKey, iv []byte, props map[string]dbus.Variant, box *secret.SecretBox) {
	block, _ := aes.NewCipher(aesKey)
	enc := cipher.NewCBCEncrypter(block, iv)
	dec := cipher.NewCBCDecrypter(block, iv)
	var evil cipher.BlockMode = fakeBlockMode{}
	_ = box.Use(func(plain []byte) error {
		// 反例 1：全局 dbusSecret 与非 Value 字段写入必须拒绝
		globalDBusSecret.Value = plain // want "禁止将明文机密存入结构体或非字节切片容器字面量"
		localBad := dbusSecret{Session: sess, Parameters: plain} // want "禁止将明文机密存入结构体或非字节切片容器字面量"
		_ = localBad

		// 反例 2：非常量或未授权 D-Bus 方法、非 dbusSecret 参数必须拒绝
		sec := dbusSecret{Session: sess, Value: plain}
		_ = obj.CallWithContext(ctx, dynMethod, 0, props, sec, true)                   // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_ = obj.CallWithContext(ctx, "org.freedesktop.DBus.ListNames", 0, sec)         // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_ = obj.CallWithContext(ctx, "org.freedesktop.Secret.Collection.CreateItem", 0, props, string(plain), true) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"

		// 反例 3：CBC 解密器/伪造 BlockMode/外层 dst/原地覆盖 dst/染毒 IV 必须拒绝
		localDst := make([]byte, len(plain))
		dec.CryptBlocks(localDst, plain)        // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		evil.CryptBlocks(localDst, plain)       // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		enc.CryptBlocks(leakedCipherBuf, plain) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		enc.CryptBlocks(plain, plain)           // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		_ = cipher.NewCBCEncrypter(block, plain) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"

		// 反例 4：跨子包借用 purego 或日志泄漏必须拒绝
		_, _, _ = purego.SyscallN(1, uintptr(len(plain)), uintptr(plain[0])) // want "禁止将明文机密传入未经授权的外部调用或未知汇点"
		slog.Info("ss-leak", "v", string(plain))                              // want "禁止将明文机密.*传入日志汇点"
		return nil
	})
}
