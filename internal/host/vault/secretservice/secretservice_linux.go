//go:build linux

package secretservice

import (
	"bytes"
	"context"
	"crypto/aes"
	"errors"
	"fmt"
	"io"

	"github.com/godbus/dbus/v5"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	dbusServiceName       = "org.freedesktop.secrets"
	dbusServicePath       = "/org/freedesktop/secrets"
	dbusDefaultCollection = "/org/freedesktop/secrets/aliases/default"
	dbusIfaceService      = "org.freedesktop.Secret.Service"
	dbusIfaceSession      = "org.freedesktop.Secret.Session"
	dbusIfaceCollection   = "org.freedesktop.Secret.Collection"
	dbusIfaceItem         = "org.freedesktop.Secret.Item"
	dbusAlgoDH            = "dh-ietf1024-sha256-aes128-cbc-pkcs7"
	dbusAlgoPlain         = "plain"
	dbusContentTypeBin    = "application/octet-stream"
)

// Spec 是构造 Linux FreeDesktop Secret Service 凭据库适配器 Store 的显式入参规格。
type Spec struct {
	Env                ports.EnvPort
	Entropy            ports.Entropy
	BusAddress         string // 可选显式地址；为空时从 Env.LookupEnv("DBUS_SESSION_BUS_ADDRESS") 读取
	AllowPlainFallback bool   // 当服务端不支持 DH 时是否允许回退 plain 会话（默认建议 true）
}

// dbusSecret 精确匹配 org.freedesktop.Secret.Secret 的 D-Bus 线缆结构 (oayays)。
type dbusSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// Store 实现 ports.SecretVault，通过 Linux FreeDesktop Secret Service D-Bus 协议安全存取凭据；零值恒无效。
//
//xops:opaque
//xops:failclosed
type Store struct {
	env                ports.EnvPort
	entropy            ports.Entropy
	busAddress         string
	allowPlainFallback bool
	valid              bool
}

// NewStore 校验熵源与环境端口并构造 Linux Secret Service 适配器。
func NewStore(spec Spec) (*Store, error) {
	if spec.Entropy == nil {
		return nil, fmt.Errorf("%w: secretservice Entropy 不能为 nil", ports.ErrInvalidArgument)
	}
	if spec.BusAddress == "" && spec.Env == nil {
		return nil, fmt.Errorf("%w: 未显式指定 BusAddress 时必须注入 EnvPort", ports.ErrInvalidArgument)
	}
	return &Store{
		env:                spec.Env,
		entropy:            spec.Entropy,
		busAddress:         spec.BusAddress,
		allowPlainFallback: spec.AllowPlainFallback,
		valid:              true,
	}, nil
}

type ssSession struct {
	conn   *dbus.Conn
	path   dbus.ObjectPath
	aesKey []byte
}

func (sess *ssSession) close(ctx context.Context) {
	if sess.aesKey != nil {
		clear(sess.aesKey)
		sess.aesKey = nil
	}
	if sess.conn != nil {
		if sess.path != "" && sess.path != "/" {
			_ = sess.conn.Object(dbusServiceName, sess.path).CallWithContext(ctx, dbusIfaceSession+".Close", 0).Err
		}
		_ = sess.conn.Close()
		sess.conn = nil
	}
}

// WithSecret 搜索并读取 Secret Service 条目，解密后在同步闭包内借出 *secret.SecretBox 并无条件清零。
//
//xops:syncclosure
//xops:borrowed
func (s *Store) WithSecret(ctx context.Context, ref secret.Ref, fn func(box *secret.SecretBox) error) error {
	if err := s.checkArgs(ctx, ref); err != nil {
		return err
	}
	if fn == nil {
		return ports.ErrNilCallback
	}
	raw, err := s.readRaw(ctx, ref)
	if err != nil {
		return err
	}
	defer clear(raw)
	return secret.WithBytes(raw, func(box *secret.SecretBox) error { return fn(box) })
}

// PutAndVerify 写入 Secret Service 条目（优先 DH AES-128-CBC，不支持时按策略回退 plain）并常量时间回读校验。
func (s *Store) PutAndVerify(
	ctx context.Context,
	ref secret.Ref,
	//xops:borrowed
	box *secret.SecretBox,
) error {
	if err := s.checkArgs(ctx, ref); err != nil {
		return err
	}
	if !box.IsValid() {
		return fmt.Errorf("%w: SecretBox 无效", ports.ErrInvalidArgument)
	}
	if err := s.writeBox(ctx, ref, box); err != nil {
		return err
	}
	verifyErr := s.WithSecret(ctx, ref, func(got *secret.SecretBox) error {
		if !got.Equal(box) {
			return ports.ErrSecretVerifyFailed
		}
		return nil
	})
	if verifyErr != nil && !errors.Is(verifyErr, ports.ErrSecretVerifyFailed) && ctx.Err() == nil {
		return fmt.Errorf("%w: %w", ports.ErrSecretVerifyFailed, verifyErr)
	}
	return verifyErr
}

// Delete 删除 Secret Service 中匹配 ref 的全部已解锁条目；若存在已锁定匹配项则失败关闭返回 ErrVaultLocked，
// 无任何匹配项返回 ports.ErrSecretNotFound。
func (s *Store) Delete(ctx context.Context, ref secret.Ref) error {
	if err := s.checkArgs(ctx, ref); err != nil {
		return err
	}
	sess, err := s.openSession(ctx)
	if err != nil {
		return err
	}
	defer sess.close(ctx)
	unlocked, locked, err := searchMatchingItems(ctx, sess.conn, ref)
	if err != nil {
		return err
	}
	if len(locked) > 0 {
		return ports.ErrVaultLocked
	}
	if len(unlocked) == 0 {
		return ports.ErrSecretNotFound
	}
	for _, itemPath := range unlocked {
		var prompt dbus.ObjectPath
		if err := sess.conn.Object(dbusServiceName, itemPath).CallWithContext(ctx, dbusIfaceItem+".Delete", 0).Store(&prompt); err != nil {
			return mapDBusError(err)
		}
		if prompt != "" && prompt != "/" {
			return ports.ErrVaultLocked
		}
	}
	return nil
}

func (s *Store) readRaw(ctx context.Context, ref secret.Ref) ([]byte, error) {
	sess, err := s.openSession(ctx)
	if err != nil {
		return nil, err
	}
	defer sess.close(ctx)
	itemPath, err := findUnlockedItem(ctx, sess.conn, ref)
	if err != nil {
		return nil, err
	}
	var sec dbusSecret
	if err := sess.conn.Object(dbusServiceName, itemPath).CallWithContext(ctx, dbusIfaceItem+".GetSecret", 0, sess.path).Store(&sec); err != nil {
		return nil, mapDBusError(err)
	}
	defer clear(sec.Value)
	if len(sess.aesKey) > 0 {
		return decryptAES128CBC(sess.aesKey, sec.Parameters, sec.Value)
	}
	out := make([]byte, len(sec.Value))
	copy(out, sec.Value)
	return out, nil
}

func (s *Store) writeBox(ctx context.Context, ref secret.Ref, box *secret.SecretBox) error {
	sess, err := s.openSession(ctx)
	if err != nil {
		return err
	}
	defer sess.close(ctx)
	coll := sess.conn.Object(dbusServiceName, dbus.ObjectPath(dbusDefaultCollection))
	if locked, lErr := isCollectionLocked(ctx, coll); lErr != nil {
		return lErr
	} else if locked {
		return ports.ErrVaultLocked
	}
	props := itemCreateProperties(ref)
	if len(sess.aesKey) > 0 {
		return s.createItemDH(ctx, coll, sess, props, box)
	}
	return createItemPlain(ctx, coll, sess.path, props, box)
}

func (s *Store) createItemDH(ctx context.Context, coll dbus.BusObject, sess *ssSession, props map[string]dbus.Variant, box *secret.SecretBox) error {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(s.entropy, iv); err != nil {
		return fmt.Errorf("%w: %w", ports.ErrEntropyShortRead, err)
	}
	ct, err := encryptBoxAES128CBC(sess.aesKey, iv, box)
	if err != nil {
		return err
	}
	sec := dbusSecret{
		Session:     sess.path,
		Parameters:  iv,
		Value:       ct,
		ContentType: dbusContentTypeBin,
	}
	var item, prompt dbus.ObjectPath
	if err := coll.CallWithContext(ctx, "org.freedesktop.Secret.Collection.CreateItem", 0, props, sec, true).Store(&item, &prompt); err != nil {
		return mapDBusError(err)
	}
	if prompt != "" && prompt != "/" {
		return ports.ErrVaultLocked
	}
	return nil
}

func createItemPlain(ctx context.Context, coll dbus.BusObject, sessPath dbus.ObjectPath, props map[string]dbus.Variant, box *secret.SecretBox) error {
	var prompt dbus.ObjectPath
	err := box.Use(func(plain []byte) error {
		// 复制为本作用域自持独立切片，满足 linearlease 借用零别名不变量，同时仍完整受 secrettaint 窄钩子审计并立即 clear 零化。
		localVal := bytes.Clone(plain)
		defer clear(localVal)
		sec := dbusSecret{
			Session:     sessPath,
			Value:       localVal,
			ContentType: dbusContentTypeBin,
		}
		var item dbus.ObjectPath
		call := coll.CallWithContext(ctx, "org.freedesktop.Secret.Collection.CreateItem", 0, props, sec, true)
		return call.Store(&item, &prompt)
	})
	if err != nil {
		return mapDBusError(err)
	}
	if prompt != "" && prompt != "/" {
		return ports.ErrVaultLocked
	}
	return nil
}

func (s *Store) openSession(ctx context.Context) (*ssSession, error) {
	addr := s.busAddress
	if addr == "" && s.env != nil {
		addr, _ = s.env.LookupEnv("DBUS_SESSION_BUS_ADDRESS")
	}
	sock, err := ParseSessionBusUnixSocket(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ports.ErrUnsupported, err)
	}
	ctrlPath, err := osfs.ValidateControlSocketPath(sock)
	if err != nil {
		return nil, fmt.Errorf("%w: D-Bus 套接字路径安全校验失败: %w", ports.ErrUnsupported, err)
	}
	rawConn, _, err := osfs.DialUnixVerified(ctx, ctrlPath)
	if err != nil {
		if cErr := ctx.Err(); cErr != nil {
			return nil, cErr
		}
		return nil, fmt.Errorf("%w: 连接并核验 D-Bus 会话总线失败: %w", ports.ErrUnsupported, err)
	}
	conn, err := dbus.NewConn(rawConn)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("%w: 创建 D-Bus 连接失败: %w", ports.ErrUnsupported, err)
	}
	stopHandshake := context.AfterFunc(ctx, func() { _ = conn.Close() })
	authErr := conn.Auth(nil)
	var helloErr error
	if authErr == nil {
		helloErr = conn.Hello()
	}
	stopHandshake()
	if cErr := ctx.Err(); cErr != nil {
		_ = conn.Close()
		return nil, cErr
	}
	if authErr != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: D-Bus 认证失败: %w", ports.ErrUnsupported, authErr)
	}
	if helloErr != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: D-Bus Hello 失败: %w", ports.ErrUnsupported, helloErr)
	}
	sess, err := s.negotiateSession(ctx, conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return sess, nil
}

func (s *Store) negotiateSession(ctx context.Context, conn *dbus.Conn) (*ssSession, error) {
	svc := conn.Object(dbusServiceName, dbus.ObjectPath(dbusServicePath))
	if sess, err := s.tryOpenDHSession(ctx, conn, svc); err == nil {
		return sess, nil
	} else if !s.allowPlainFallback || !isDBusNotSupported(err) {
		return nil, normalizeDHSessionErr(err)
	}
	var out dbus.Variant
	var path dbus.ObjectPath
	if err := svc.CallWithContext(ctx, dbusIfaceService+".OpenSession", 0, dbusAlgoPlain, dbus.MakeVariant("")).Store(&out, &path); err != nil {
		return nil, mapDBusError(err)
	}
	return &ssSession{conn: conn, path: path}, nil
}

func normalizeDHSessionErr(err error) error {
	if errors.Is(err, ports.ErrEntropyShortRead) || errors.Is(err, ports.ErrCorruptData) {
		return err
	}
	return mapDBusError(err)
}

func (s *Store) tryOpenDHSession(ctx context.Context, conn *dbus.Conn, svc dbus.BusObject) (*ssSession, error) {
	kp, err := generateDHKeyPair(s.entropy)
	if err != nil {
		return nil, err
	}
	defer clear(kp.priv.Bits())
	var out dbus.Variant
	var path dbus.ObjectPath
	if err := svc.CallWithContext(ctx, dbusIfaceService+".OpenSession", 0, dbusAlgoDH, dbus.MakeVariant(kp.pub)).Store(&out, &path); err != nil {
		return nil, err
	}
	peerPub, ok := out.Value().([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: D-Bus OpenSession 返回非字节 DH 公钥", ports.ErrCorruptData)
	}
	aesKey, err := deriveDHAES128Key(kp.priv, peerPub)
	if err != nil {
		return nil, err
	}
	return &ssSession{conn: conn, path: path, aesKey: aesKey}, nil
}

func searchMatchingItems(ctx context.Context, conn *dbus.Conn, ref secret.Ref) (unlocked, locked []dbus.ObjectPath, err error) {
	coll := conn.Object(dbusServiceName, dbus.ObjectPath(dbusDefaultCollection))
	if isLocked, lErr := isCollectionLocked(ctx, coll); lErr != nil {
		return nil, nil, lErr
	} else if isLocked {
		return nil, nil, ports.ErrVaultLocked
	}
	svc := conn.Object(dbusServiceName, dbus.ObjectPath(dbusServicePath))
	if err := svc.CallWithContext(ctx, dbusIfaceService+".SearchItems", 0, itemAttrs(ref)).Store(&unlocked, &locked); err != nil {
		return nil, nil, mapDBusError(err)
	}
	return unlocked, locked, nil
}

func findUnlockedItem(ctx context.Context, conn *dbus.Conn, ref secret.Ref) (dbus.ObjectPath, error) {
	unlocked, locked, err := searchMatchingItems(ctx, conn, ref)
	if err != nil {
		return "", err
	}
	if len(unlocked) > 0 {
		return unlocked[0], nil
	}
	if len(locked) > 0 {
		return "", ports.ErrVaultLocked
	}
	return "", ports.ErrSecretNotFound
}

func isCollectionLocked(ctx context.Context, coll dbus.BusObject) (bool, error) {
	var v dbus.Variant
	if err := coll.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, dbusIfaceCollection, "Locked").Store(&v); err != nil {
		return true, mapDBusError(err)
	}
	locked, ok := v.Value().(bool)
	if !ok {
		return true, fmt.Errorf("%w: Collection.Locked 属性类型异常", ports.ErrCorruptData)
	}
	return locked, nil
}

func itemAttrs(ref secret.Ref) map[string]string {
	return map[string]string{
		"application": "xops",
		"xops_store":  ref.Store(),
		"xops_item":   ref.Item(),
	}
}

func itemCreateProperties(ref secret.Ref) map[string]dbus.Variant {
	return map[string]dbus.Variant{
		"org.freedesktop.Secret.Item.Label":      dbus.MakeVariant("xops:" + ref.String()),
		"org.freedesktop.Secret.Item.Attributes": dbus.MakeVariant(itemAttrs(ref)),
	}
}

func isDBusNotSupported(err error) bool {
	if de, ok := errors.AsType[dbus.Error](err); ok {
		return de.Name == "org.freedesktop.DBus.Error.NotSupported"
	}
	return false
}

func mapDBusError(err error) error {
	if err == nil {
		return nil
	}
	if de, ok := errors.AsType[dbus.Error](err); ok {
		switch de.Name {
		case "org.freedesktop.Secret.Error.IsLocked":
			return ports.ErrVaultLocked
		case "org.freedesktop.Secret.Error.NoSuchObject":
			return ports.ErrSecretNotFound
		case "org.freedesktop.DBus.Error.AccessDenied":
			return ports.ErrPermissionDenied
		}
	}
	return fmt.Errorf("%w: Secret Service D-Bus 调用失败: %w", ports.ErrUnsupported, err)
}

func (s *Store) checkArgs(ctx context.Context, ref secret.Ref) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || !s.valid {
		return fmt.Errorf("%w: secretservice Store 未初始化", ports.ErrInvalidArgument)
	}
	if !ref.IsValid() {
		return fmt.Errorf("%w: 无效凭据引用", ports.ErrInvalidArgument)
	}
	return nil
}
