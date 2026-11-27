package offline

import (
	"context"
	"crypto/cipher"
	"errors"
	"io"
	"slices"
	"sync"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/host/vault/helper"
	"github.com/wentf9/xops-cli/internal/i18n"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Spec 是构造离线加密 dirfd 凭据库 Vault 的显式入参规格（非持久化 DTO）。
type Spec struct {
	ScopedFS   ports.ScopedRootFS
	RootDir    pathalg.LocalDir
	Entropy    ports.Entropy
	KDFParams  helper.Argon2idParams // 为零值时自动采用安全默认参数 DefaultArgon2idParams()
	KDFProcess ports.ProcessPort     // 可选：非 nil 时通过隔离 KDF 子进程执行 Argon2id
	KDFSpec    ports.ProcessSpec     // 当 KDFProcess 非 nil 时必填
	StoreNames []string              // 可选：向 VaultStatus.KnownStores 声明的受管存储名（默认 ["offline"]）
}

// Vault 同时实现 ports.SecretVault 与 ports.VaultControlPort，提供基于 *os.Root 沙箱与旁路锁的
// Argon2id + XChaCha20-Poly1305 离线加密凭据库；零值恒无效并严格失败关闭。
//
//xops:opaque
//xops:failclosed
type Vault struct {
	fs         ports.ScopedRootFS
	rootDir    pathalg.LocalDir
	entropy    io.Reader
	kdfParams  helper.Argon2idParams
	kdfProc    ports.ProcessPort
	kdfSpec    ports.ProcessSpec
	storeNames []string

	mu    sync.RWMutex
	aead  cipher.AEAD
	valid bool
}

// NewVault 校验沙箱 FS、根目录、熵源与可选隔离 KDF 规格并构造离线加密凭据库实例。
func NewVault(spec Spec) (*Vault, error) {
	if spec.ScopedFS == nil || !spec.RootDir.IsValid() || spec.Entropy == nil {
		return nil, i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostInvalidField, i18n.Str("field", "ScopedFS/RootDir/Entropy"))
	}
	params := spec.KDFParams
	if !params.IsValid() {
		params = helper.DefaultArgon2idParams()
	}
	if spec.KDFProcess != nil && !spec.KDFSpec.IsValid() {
		return nil, i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostInvalidField, i18n.Str("field", "KDFSpec"))
	}
	stores := slices.Clone(spec.StoreNames)
	if len(stores) == 0 {
		stores = []string{defaultStoreName}
	}
	return &Vault{
		fs:         spec.ScopedFS,
		rootDir:    spec.RootDir,
		entropy:    spec.Entropy,
		kdfParams:  params,
		kdfProc:    spec.KDFProcess,
		kdfSpec:    spec.KDFSpec,
		storeNames: stores,
		valid:      true,
	}, nil
}

// Init 使用借用的主口令初始化离线凭据库并立即进入已解锁态；若凭据库已存在则返回 ports.ErrAlreadyExists。
func (v *Vault) Init(
	ctx context.Context,
	//xops:borrowed
	pass *secret.SecretBox,
) error {
	if err := v.checkControlArgs(ctx, pass, true); err != nil {
		return err
	}
	if err := v.fs.EnsureRoot(v.rootDir, vaultDirPerm); err != nil {
		return err
	}
	var salt [vaultSaltBytes]byte
	dek := make([]byte, vaultDEKBytes)
	wrapNonce := make([]byte, vaultNonceBytes)
	defer clear(dek)
	if err := v.fillRandom(salt[:], dek, wrapNonce); err != nil {
		return err
	}
	kekAEAD, err := v.deriveKEKAEAD(ctx, v.kdfParams, salt, pass)
	if err != nil {
		return err
	}
	wrappedDEK := kekAEAD.Seal(nil, wrapNonce, dek, []byte(dekAAD))
	dataAEAD, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return err
	}
	metaBytes, err := encodeVaultMeta(parsedVaultMeta{
		params:     v.kdfParams,
		salt:       salt,
		wrapNonce:  wrapNonce,
		wrappedDEK: wrappedDEK,
		stores:     v.storeNames,
	})
	if err != nil {
		return err
	}
	if err := v.writeMetaExclusive(ctx, metaBytes); err != nil {
		return err
	}
	v.mu.Lock()
	v.aead = dataAEAD
	v.mu.Unlock()
	return nil
}

// Unlock 读取元数据并使用借用的主口令派生 KEK 解包 DEK；未初始化返回 ErrNotFound，口令错误返回 ErrAuthFailed。
func (v *Vault) Unlock(
	ctx context.Context,
	//xops:borrowed
	pass *secret.SecretBox,
) error {
	if err := v.checkControlArgs(ctx, pass, true); err != nil {
		return err
	}
	meta, err := v.loadMeta(ctx)
	if err != nil {
		return err
	}
	kekAEAD, err := v.deriveKEKAEAD(ctx, meta.params, meta.salt, pass)
	if err != nil {
		return err
	}
	dek, err := kekAEAD.Open(nil, meta.wrapNonce, meta.wrappedDEK, []byte(dekAAD))
	if err != nil {
		return ports.ErrAuthFailed
	}
	defer clear(dek)
	dataAEAD, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.aead = dataAEAD
	v.storeNames = slices.Clone(meta.stores)
	v.mu.Unlock()
	return nil
}

// Lock 无条件清空内存中的 AEAD 解锁句柄并进入锁定态；若本就处于未解锁态且磁盘尚未初始化则返回 ports.ErrNotFound。
func (v *Vault) Lock(ctx context.Context) error {
	if err := v.checkControlArgs(ctx, nil, false); err != nil {
		return err
	}
	v.mu.Lock()
	wasUnlocked := v.aead != nil
	v.aead = nil
	v.mu.Unlock()
	if wasUnlocked {
		return nil
	}
	if _, err := v.loadMeta(ctx); err != nil {
		return err
	}
	return nil
}

// Status 查询离线凭据库当前生命周期状态（Uninitialized / Locked / Unlocked）与已知存储清单。
func (v *Vault) Status(ctx context.Context) (ports.VaultStatus, error) {
	var zero ports.VaultStatus
	if err := v.checkControlArgs(ctx, nil, false); err != nil {
		return zero, err
	}
	v.mu.RLock()
	unlocked := v.aead != nil
	stores := slices.Clone(v.storeNames)
	v.mu.RUnlock()
	if unlocked {
		return ports.NewVaultStatus(ports.VaultStatusSpec{
			State:       ports.VaultStateUnlocked,
			KnownStores: stores,
			Detail:      "offline-xchacha20poly1305",
		})
	}
	meta, err := v.loadMeta(ctx)
	if errors.Is(err, ports.ErrNotFound) {
		return ports.NewVaultStatus(ports.VaultStatusSpec{
			State:       ports.VaultStateUninitialized,
			KnownStores: stores,
			Detail:      "offline-xchacha20poly1305",
		})
	}
	if err != nil {
		return zero, err
	}
	return ports.NewVaultStatus(ports.VaultStatusSpec{
		State:       ports.VaultStateLocked,
		KnownStores: meta.stores,
		Detail:      "offline-xchacha20poly1305",
	})
}

// WithSecret 解密指定凭据条目并在同步闭包内借出 *secret.SecretBox，退出前无条件清零底层明文。
//
//xops:syncclosure
//xops:borrowed
func (v *Vault) WithSecret(ctx context.Context, ref secret.Ref, fn func(box *secret.SecretBox) error) error {
	if err := v.checkSecretArgs(ctx, ref); err != nil {
		return err
	}
	if fn == nil {
		return ports.ErrNilCallback
	}
	aead, err := v.currentAEAD()
	if err != nil {
		return err
	}
	raw, err := v.readItemRaw(ctx, ref)
	if err != nil {
		return err
	}
	plain, err := decryptItem(aead, ref, raw)
	if err != nil {
		return err
	}
	defer clear(plain)
	return secret.WithBytes(plain, func(box *secret.SecretBox) error { return fn(box) })
}

// PutAndVerify 在旁路独占锁保护下以 XChaCha20-Poly1305 原子加密落盘，随后重读文件解密并执行
// 常量时间 SecretBox.Equal 回读校验；若校验失败则自动回滚旧密文或清除新建文件（INV-F3）。
func (v *Vault) PutAndVerify(
	ctx context.Context,
	ref secret.Ref,
	//xops:borrowed
	box *secret.SecretBox,
) error {
	if err := v.checkSecretArgs(ctx, ref); err != nil {
		return err
	}
	if !box.IsValid() {
		return i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostInvalidSecretBox)
	}
	encoded, aead, err := v.sealItem(ref, box)
	if err != nil {
		return err
	}
	dirDest, itemDest, err := itemDestForRef(ref)
	if err != nil {
		return err
	}
	return v.fs.WithRoot(v.rootDir, func(root ports.RootHandle) error {
		if err := root.MkdirAll(dirDest, vaultDirPerm); err != nil {
			return err
		}
		return osfs.WithSidecarLock(ctx, root, itemDest, ports.LockExclusive, vaultFilePerm, func(ports.LockedFile) error {
			return writeAndVerifyLocked(root, itemDest, aead, ref, encoded, box)
		})
	})
}

// Delete 在旁路独占锁保护下删除指定凭据密文条目；条目缺失返回 ports.ErrSecretNotFound。
// 注意：严禁删除可复用的 <item>.enc.lock 旁路锁文件，否则在 Unix 上会破坏多进程 flock inode 互斥语义。
func (v *Vault) Delete(ctx context.Context, ref secret.Ref) error {
	if err := v.checkSecretArgs(ctx, ref); err != nil {
		return err
	}
	if _, err := v.currentAEAD(); err != nil {
		return err
	}
	_, itemDest, err := itemDestForRef(ref)
	if err != nil {
		return err
	}
	return v.fs.WithRoot(v.rootDir, func(root ports.RootHandle) error {
		if _, sErr := root.Stat(itemDest); errors.Is(sErr, ports.ErrNotFound) {
			return ports.ErrSecretNotFound
		} else if sErr != nil {
			return sErr
		}
		return osfs.WithSidecarLock(ctx, root, itemDest, ports.LockExclusive, vaultFilePerm, func(ports.LockedFile) error {
			rmErr := root.Remove(itemDest)
			if errors.Is(rmErr, ports.ErrNotFound) {
				return ports.ErrSecretNotFound
			}
			return rmErr
		})
	})
}

func (v *Vault) sealItem(
	ref secret.Ref,
	//xops:borrowed
	box *secret.SecretBox,
) ([]byte, cipher.AEAD, error) {
	aead, err := v.currentAEAD()
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, vaultNonceBytes)
	if err := v.fillRandom(nonce); err != nil {
		return nil, nil, err
	}
	aad := []byte(itemAADPrefix + ref.String())
	var ct []byte
	err = box.Use(func(plain []byte) error {
		ct = aead.Seal(nil, nonce, plain, aad)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	encoded, err := encodeVaultItem(ref, nonce, ct)
	return encoded, aead, err
}

func (v *Vault) currentAEAD() (cipher.AEAD, error) {
	v.mu.RLock()
	aead := v.aead
	v.mu.RUnlock()
	if aead == nil {
		return nil, ports.ErrVaultLocked
	}
	return aead, nil
}

func (v *Vault) deriveKEKAEAD(
	ctx context.Context,
	params helper.Argon2idParams,
	salt [vaultSaltBytes]byte,
	//xops:borrowed
	pass *secret.SecretBox,
) (cipher.AEAD, error) {
	if v.kdfProc != nil {
		dk, err := helper.DeriveArgon2idSubprocess(ctx, v.kdfProc, v.kdfSpec, params, salt, pass)
		if err != nil {
			return nil, err
		}
		defer clear(dk[:])
		return chacha20poly1305.NewX(dk[:])
	}
	var aead cipher.AEAD
	err := pass.Use(func(plain []byte) error {
		dk := argon2.IDKey(plain, salt[:], params.TimeCost(), params.MemoryKiB(), params.Threads(), vaultDEKBytes)
		defer clear(dk)
		var aErr error
		aead, aErr = chacha20poly1305.NewX(dk)
		return aErr
	})
	return aead, err
}

func (v *Vault) fillRandom(bufs ...[]byte) error {
	for _, b := range bufs {
		if _, err := io.ReadFull(v.entropy, b); err != nil {
			return domi18n.WrapSentinel(ports.ErrEntropyShortRead, err)
		}
	}
	return nil
}

func (v *Vault) checkControlArgs(ctx context.Context, pass *secret.SecretBox, needPass bool) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if v == nil || !v.valid {
		return i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostNotInitialized, i18n.Str("component", "offline.Vault"))
	}
	if needPass && !pass.IsValid() {
		return i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostInvalidSecretBox)
	}
	return nil
}

func (v *Vault) checkSecretArgs(ctx context.Context, ref secret.Ref) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if v == nil || !v.valid {
		return i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostNotInitialized, i18n.Str("component", "offline.Vault"))
	}
	if !ref.IsValid() {
		return i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostInvalidSecretRef)
	}
	return nil
}
