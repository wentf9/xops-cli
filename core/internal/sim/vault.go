package sim

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/internal/sim/memtree"
	"github.com/wentf9/xops-cli/core/ports"
	"io"
)

// SeededRand 是基于 SplitMix64 + xoshiro256++ 的并发安全确定性 PRNG，实现 ports.Entropy (io.Reader)。
//
//xops:opaque
//xops:failclosed
type SeededRand struct {
	simBase
	state   [4]uint64
	readErr error
}

// NewSeededRand 以 64 位种子构造跨平台逐字节一致的确定性随机与熵源。
func NewSeededRand(seed uint64) *SeededRand {
	return &SeededRand{simBase: newSimBase(nil), state: memtree.SeedXoshiro256(seed)}
}
func (r *SeededRand) nextLocked() uint64 { return memtree.NextXoshiro256(&r.state) }

// SetReadFault / Read / Uint64 / IntN / Bool / Chance / Fork / Perm 提供熵读取与随机调度。
func (r *SeededRand) SetReadFault(err error) { r.withLock(func() { r.readErr = err }) }
func (r *SeededRand) Uint64() uint64         { return withLockRet(&r.simBase, 0, r.nextLocked) }
func (r *SeededRand) Bool() bool             { return r.Uint64()&1 == 1 }
func (r *SeededRand) Fork() *SeededRand      { return NewSeededRand(r.Uint64()) }
func (r *SeededRand) Chance(num, den int) bool {
	return num > 0 && den > 0 && r.ok() && (num >= den || r.IntN(den) < num)
}
func (r *SeededRand) IntN(n int) int {
	if n <= 1 || !r.ok() {
		return 0
	}
	return int(r.Uint64() % uint64(n))
}
func (r *SeededRand) Perm(n int) []int {
	if n <= 0 {
		return nil
	}
	out := make([]int, n)
	for i := range n {
		j := r.IntN(i + 1)
		out[i], out[j] = out[j], i
	}
	return out
}
func (r *SeededRand) Read(p []byte) (int, error) {
	if !r.ok() {
		return 0, ErrSimNotInitialized
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.readErr != nil {
		return 0, r.readErr
	}
	memtree.FillXoshiro256Bytes(&r.state, p)
	return len(p), nil
}

type vaultCipherRecord struct{ nonce, ciphertext []byte }

func cloneVaultRecord(r vaultCipherRecord) vaultCipherRecord {
	return vaultCipherRecord{bytes.Clone(r.nonce), bytes.Clone(r.ciphertext)}
}

// SimVault 是采用 AES-256-GCM 静态密文存储的确定性凭据库仿真器，同时实现 ports.SecretVault 与 ports.VaultControlPort（ADR-011 / P2-T6）。
// 仅保存 AES-GCM 密文、确定性随机 Nonce 与主口令 SHA-256 摘要，0 行内 nolint，完整通过 secretbox/secrettaint/linearlease 审计。
//
//xops:opaque
//xops:failclosed
type SimVault struct {
	simBase
	vaultInited, locked, verifyMismatch bool
	masterHash, key                     [32]byte
	rng                                 *SeededRand
	entries                             map[secret.Ref]vaultCipherRecord
}

// NewSimVault 使用确定性随机源派生 AES-256 主密钥并创建已初始化且已解锁的 SimVault。
func NewSimVault(rng *SeededRand) *SimVault {
	v := NewUninitializedSimVault(rng)
	v.vaultInited, v.locked, v.masterHash = true, false, sha256.Sum256([]byte("sim-default-master"))
	return v
}

// NewUninitializedSimVault 创建处于 VaultStateUninitialized 状态的空白 SimVault，用于验证 Init/Unlock/Lock 生命周期。
func NewUninitializedSimVault(rng *SeededRand) *SimVault {
	if rng == nil {
		rng = NewSeededRand(1)
	}
	var key [32]byte
	_, _ = io.ReadFull(rng, key[:])
	return &SimVault{simBase: newSimBase(rng), locked: true, key: key, rng: rng, entries: make(map[secret.Ref]vaultCipherRecord)}
}

// Init 使用借用的主口令 SecretBox 初始化凭据库（参数级 //xops:borrowed 审计零逃逸）；已初始化返回 ErrAlreadyExists。
func (v *SimVault) Init(
	ctx context.Context,
	//xops:borrowed
	pass *secret.SecretBox,
) error {
	if err := v.check(ctx, "vault.init", pass != nil && pass.IsValid()); err != nil {
		return err
	}
	sum, err := hashSecretBox(pass)
	if err != nil {
		return err
	}
	return withLockRet(&v.simBase, ErrSimNotInitialized, func() error {
		if v.vaultInited {
			return ports.ErrAlreadyExists
		}
		v.vaultInited, v.locked, v.masterHash = true, false, sum
		return nil
	})
}

// Unlock 使用借用的主口令 SecretBox 解锁凭据库（参数级 //xops:borrowed 审计零逃逸）；未初始化返回 ErrNotFound，口令失配返回 ErrAuthFailed。
func (v *SimVault) Unlock(
	ctx context.Context,
	//xops:borrowed
	pass *secret.SecretBox,
) error {
	if err := v.check(ctx, "vault.unlock", pass != nil && pass.IsValid()); err != nil {
		return err
	}
	sum, err := hashSecretBox(pass)
	if err != nil {
		return err
	}
	return withLockRet(&v.simBase, ErrSimNotInitialized, func() error {
		if !v.vaultInited {
			return ports.ErrNotFound
		}
		if subtle.ConstantTimeCompare(v.masterHash[:], sum[:]) != 1 {
			return ports.ErrAuthFailed
		}
		v.locked = false
		return nil
	})
}

// Lock 锁定凭据库（实现 ports.VaultControlPort）；未初始化返回 ErrNotFound。
func (v *SimVault) Lock(ctx context.Context) error {
	if err := v.check(ctx, "vault.lock"); err != nil {
		return err
	}
	return withLockRet(&v.simBase, ErrSimNotInitialized, func() error {
		if !v.vaultInited {
			return ports.ErrNotFound
		}
		v.locked = true
		return nil
	})
}

// Status 返回当前凭据库生命周期状态快照（实现 ports.VaultControlPort）。
func (v *SimVault) Status(ctx context.Context) (out ports.VaultStatus, err error) {
	if err = v.check(ctx, "vault.status"); err != nil {
		return out, err
	}
	state := withLockRet(&v.simBase, ports.VaultStateInvalid, func() ports.VaultState {
		switch {
		case !v.vaultInited:
			return ports.VaultStateUninitialized
		case v.locked:
			return ports.VaultStateLocked
		default:
			return ports.VaultStateUnlocked
		}
	})
	return ports.NewVaultStatus(ports.VaultStatusSpec{State: state, KnownStores: []string{"sim-aes256gcm"}, Detail: "sim-vault"})
}

// SetVerifyMismatch / IsLocked / CiphertextFor / TamperCiphertext 控制测试故障与密文观测。
func (v *SimVault) SetVerifyMismatch(en bool) { v.withLock(func() { v.verifyMismatch = en }) }
func (v *SimVault) IsLocked() bool {
	return withLockRet(&v.simBase, true, func() bool { return !v.vaultInited || v.locked })
}
func (v *SimVault) CiphertextFor(ref secret.Ref) (ct []byte, ok bool) {
	if ref.IsValid() {
		v.withLock(func() { rec, ex := v.entries[ref]; ct, ok = bytes.Clone(rec.ciphertext), ex })
	}
	return ct, ok
}
func (v *SimVault) TamperCiphertext(ref secret.Ref) bool {
	return ref.IsValid() && withLockRet(&v.simBase, false, func() bool {
		if rec, ok := v.entries[ref]; ok && len(rec.ciphertext) > 0 {
			rec.ciphertext[0] ^= 0xff
			v.entries[ref] = rec
			return true
		}
		return false
	})
}

// WithSecret 解密静态密文并在同步闭包内借出 *secret.SecretBox，退出前无条件清零底层明文。
//
//xops:syncclosure
//xops:borrowed
func (v *SimVault) WithSecret(ctx context.Context, ref secret.Ref, fn func(box *secret.SecretBox) error) error {
	if err := v.checkFn(ctx, fn != nil, "vault.get", ref.IsValid()); err != nil {
		return err
	}
	var stored vaultCipherRecord
	if err := withLockRet(&v.simBase, ErrSimNotInitialized, func() error {
		if !v.vaultInited || v.locked {
			return ports.ErrVaultLocked
		}
		r, ok := v.entries[ref]
		if !ok {
			return ports.ErrSecretNotFound
		}
		stored = cloneVaultRecord(r)
		return nil
	}); err != nil {
		return err
	}
	plain, err := openAESGCM(v.key, stored, []byte(ref.String()))
	if err != nil {
		return fmt.Errorf("%w: %w", ports.ErrCorruptData, err)
	}
	defer clear(plain)
	return secret.WithBytes(plain, func(box *secret.SecretBox) error { return fn(box) })
}

// PutAndVerify 以 AES-256-GCM 加密写入 ref，从存储读回密文解密并执行常量时间 Equal 校验；失败则原子回滚旧条目（INV-F3）。
func (v *SimVault) PutAndVerify(
	ctx context.Context,
	ref secret.Ref,
	//xops:borrowed
	box *secret.SecretBox,
) error {
	if err := v.check(ctx, "vault.put", ref.IsValid(), box.IsValid()); err != nil {
		return err
	}
	rec, err := sealSecretBox(v.key, v.rng, []byte(ref.String()), box)
	if err != nil {
		return err
	}
	v.mu.Lock()
	locked, mismatch := !v.vaultInited || v.locked, v.verifyMismatch
	prev, hadPrev := v.entries[ref]
	var stored vaultCipherRecord
	if !locked {
		v.entries[ref] = cloneVaultRecord(rec)
		stored = cloneVaultRecord(v.entries[ref])
	}
	v.mu.Unlock()
	if locked {
		return ports.ErrVaultLocked
	}
	if err := v.verifyStoredRecord(ref, stored, mismatch, box); err != nil {
		v.withLock(func() {
			if hadPrev {
				v.entries[ref] = prev
			} else {
				delete(v.entries, ref)
			}
		})
		return err
	}
	return nil
}
func (v *SimVault) verifyStoredRecord(ref secret.Ref, stored vaultCipherRecord, mismatch bool, box *secret.SecretBox) error {
	plain, err := openAESGCM(v.key, stored, []byte(ref.String()))
	if err != nil {
		return fmt.Errorf("%w: %w", ports.ErrSecretVerifyFailed, err)
	}
	defer clear(plain)
	rbBytes := plain
	if mismatch {
		n := len(plain)
		clear(plain)
		rbBytes = make([]byte, n+1)
	}
	return secret.WithBytes(rbBytes, func(rb *secret.SecretBox) error {
		if !rb.Equal(box) {
			return ports.ErrSecretVerifyFailed
		}
		return nil
	})
}

// Delete 删除 ref 对应的静态密文记录。
func (v *SimVault) Delete(ctx context.Context, ref secret.Ref) error {
	if err := v.check(ctx, "vault.delete", ref.IsValid()); err != nil {
		return err
	}
	return withLockRet(&v.simBase, ErrSimNotInitialized, func() error {
		if !v.vaultInited || v.locked {
			return ports.ErrVaultLocked
		}
		if _, ok := v.entries[ref]; !ok {
			return ports.ErrSecretNotFound
		}
		delete(v.entries, ref)
		return nil
	})
}
func hashSecretBox(box *secret.SecretBox) (sum [32]byte, err error) {
	err = box.Use(func(plain []byte) error {
		h := sha256.New()
		_, _ = h.Write(plain)
		h.Sum(sum[:0])
		return nil
	})
	return sum, err
}
func sealSecretBox(key [32]byte, rng io.Reader, aad []byte, box *secret.SecretBox) (rec vaultCipherRecord, err error) {
	err = box.Use(func(plain []byte) error {
		block, bErr := aes.NewCipher(key[:])
		if bErr != nil {
			return bErr
		}
		aead, gErr := cipher.NewGCM(block)
		if gErr != nil {
			return gErr
		}
		nBuf := make([]byte, aead.NonceSize())
		if _, rErr := io.ReadFull(rng, nBuf); rErr != nil {
			return rErr
		}
		rec = vaultCipherRecord{nBuf, aead.Seal(nil, nBuf, plain, aad)}
		return nil
	})
	return rec, err
}
func openAESGCM(key [32]byte, rec vaultCipherRecord, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(rec.nonce) != aead.NonceSize() {
		return nil, ports.ErrCorruptData
	}
	return aead.Open(nil, rec.nonce, rec.ciphertext, aad)
}
