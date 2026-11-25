package sim

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"net"
	"slices"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
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
	sm := seed
	var st [4]uint64
	for i := range st {
		sm += 0x9e3779b97f4a7c15
		z := (sm ^ (sm >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		st[i] = z ^ (z >> 31)
	}
	if st == ([4]uint64{}) {
		st[0] = 0x9e3779b97f4a7c15
	}
	return &SeededRand{simBase: newSimBase(nil), state: st}
}
func (r *SeededRand) nextLocked() uint64 {
	s := &r.state
	res, t := bits.RotateLeft64(s[0]+s[3], 23)+s[0], s[1]<<17
	s[2] ^= s[0]
	s[3] ^= s[1]
	s[1] ^= s[2]
	s[0] ^= s[3]
	s[2] ^= t
	s[3] = bits.RotateLeft64(s[3], 45)
	return res
}

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
	var buf [8]byte
	for off := 0; off < len(p); off += 8 {
		binary.LittleEndian.PutUint64(buf[:], r.nextLocked())
		copy(p[off:], buf[:])
	}
	if len(p) >= 16 && !slices.ContainsFunc(p, func(b byte) bool { return b != 0 }) {
		p[0] = 1
	}
	return len(p), nil
}

type vaultCipherRecord struct{ nonce, ciphertext []byte }

func cloneVaultRecord(r vaultCipherRecord) vaultCipherRecord {
	return vaultCipherRecord{bytes.Clone(r.nonce), bytes.Clone(r.ciphertext)}
}

// SimVault 是采用 AES-256-GCM 静态密文存储的确定性凭据库仿真器，实现 ports.SecretVault（ADR-011 / P2-T6）。
// 仅保存 AES-GCM 密文与确定性随机 Nonce，0 行内 nolint，完整通过 secretbox/secrettaint/linearlease 审计。
//
//xops:opaque
//xops:failclosed
type SimVault struct {
	simBase
	locked, verifyMismatch bool
	key                    [32]byte
	rng                    *SeededRand
	entries                map[secret.Ref]vaultCipherRecord
}

// NewSimVault 使用确定性随机源派生 AES-256 主密钥并创建已解锁的 SimVault。
func NewSimVault(rng *SeededRand) *SimVault {
	if rng == nil {
		rng = NewSeededRand(1)
	}
	var key [32]byte
	_, _ = io.ReadFull(rng, key[:])
	return &SimVault{simBase: newSimBase(rng), key: key, rng: rng, entries: make(map[secret.Ref]vaultCipherRecord)}
}

// Lock / Unlock / IsLocked / SetVerifyMismatch / CiphertextFor / TamperCiphertext 控制凭据库状态。
func (v *SimVault) Lock()                     { v.withLock(func() { v.locked = true }) }
func (v *SimVault) Unlock()                   { v.withLock(func() { v.locked = false }) }
func (v *SimVault) SetVerifyMismatch(en bool) { v.withLock(func() { v.verifyMismatch = en }) }
func (v *SimVault) IsLocked() bool {
	return withLockRet(&v.simBase, true, func() bool { return v.locked })
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
		if v.locked {
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
func (v *SimVault) PutAndVerify(ctx context.Context, ref secret.Ref, box *secret.SecretBox) error {
	if err := v.check(ctx, "vault.put", ref.IsValid(), box.IsValid()); err != nil {
		return err
	}
	rec, err := sealSecretBox(v.key, v.rng, []byte(ref.String()), box)
	if err != nil {
		return err
	}
	v.mu.Lock()
	locked, mismatch := v.locked, v.verifyMismatch
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
		if v.locked {
			return ports.ErrVaultLocked
		}
		if _, ok := v.entries[ref]; !ok {
			return ports.ErrSecretNotFound
		}
		delete(v.entries, ref)
		return nil
	})
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

// ProcessHandler 定义 SimProcessPort 的可编程命令处理回调。
type ProcessHandler func(ctx context.Context, spec ports.ProcessSpec, stdin []byte) (ports.ProcessResult, error)

// SimProcessPort 是零 os/exec 的纯内存子进程与 stdio 管道仿真器，实现 ports.ProcessPort。
//
//xops:opaque
//xops:failclosed
type SimProcessPort struct {
	simBase
	handlers map[string]ProcessHandler
}

// NewSimProcessPort 创建纯内存子进程仿真器（"fail"/"false" 返回退出码 1，其余默认回显 stdin）。
func NewSimProcessPort() *SimProcessPort {
	return &SimProcessPort{simBase: newSimBase(nil), handlers: make(map[string]ProcessHandler)}
}

// RegisterCommand 注册或注销指定命令名的自定义处理回调。
func (p *SimProcessPort) RegisterCommand(cmd string, fn ProcessHandler) {
	if cmd != "" {
		p.withLock(func() {
			if fn == nil {
				delete(p.handlers, cmd)
			} else {
				p.handlers[cmd] = fn
			}
		})
	}
}
func (p *SimProcessPort) Run(ctx context.Context, spec ports.ProcessSpec, stdin io.Reader) (out ports.ProcessResult, err error) {
	if err = p.check(ctx, "proc.run", spec.IsValid()); err != nil {
		return out, err
	}
	var inBytes []byte
	if stdin != nil {
		if inBytes, err = io.ReadAll(stdin); err != nil {
			return out, err
		}
	}
	if h := withLockRet(&p.simBase, nil, func() ProcessHandler { return p.handlers[spec.Command()] }); h != nil {
		return h(ctx, spec, inBytes)
	}
	if spec.Command() == "fail" || spec.Command() == "false" {
		return ports.NewProcessResult(ports.ProcessResultSpec{ExitStatus: execution.NewExitCode(1), Stderr: []byte("simulated non-zero exit")})
	}
	trunc := uint64(len(inBytes)) > spec.MaxOutputBytes()
	if trunc {
		inBytes = inBytes[:spec.MaxOutputBytes()]
	}
	return ports.NewProcessResult(ports.ProcessResultSpec{ExitStatus: execution.NewExitCode(0), Stdout: inBytes, Truncated: trunc})
}
func (p *SimProcessPort) DialStdio(ctx context.Context, spec ports.ProcessSpec) (net.Conn, error) {
	if err := p.check(ctx, "proc.dialstdio", spec.IsValid()); err != nil {
		return nil, err
	}
	return &simEchoConn{addr: simAddr(spec.Command())}, nil
}

// SimTerminalPort 实现 ports.TerminalPort 的纯内存 PTY/ConPTY 与孤儿进程组判定仿真器。
//
//xops:opaque
//xops:failclosed
type SimTerminalPort struct {
	simBase
	interactive bool
	size        ports.TerminalSize
	suspendErr  error
	suspendV    security.Verdict
}

// NewSimTerminalPort 创建纯内存终端仿真器（cols/rows 为 0 时默认 80x24）。
func NewSimTerminalPort(interactive bool, cols, rows uint16) *SimTerminalPort {
	sz, err := ports.NewTerminalSize(cols, rows)
	if err != nil {
		sz, _ = ports.NewTerminalSize(80, 24)
	}
	return &SimTerminalPort{simBase: newSimBase(nil), interactive: interactive, size: sz, suspendV: security.VerdictAllow}
}

// SetSuspendResult 配置孤儿进程组暂停安全判定返回值与错误注入。
func (t *SimTerminalPort) SetSuspendResult(v security.Verdict, err error) {
	t.withLock(func() { t.suspendV, t.suspendErr = v, err })
}
func (t *SimTerminalPort) IsInteractive() bool {
	return withLockRet(&t.simBase, false, func() bool { return t.interactive })
}
func (t *SimTerminalPort) Size() (out ports.TerminalSize, err error) {
	return out, withLockRet(&t.simBase, ErrSimNotInitialized, func() error {
		if !t.interactive {
			return ports.ErrUnsupported
		}
		out = t.size
		return nil
	})
}
func (t *SimTerminalPort) CanSuspendProcessGroup() (v security.Verdict, err error) {
	if !t.ok() {
		return security.VerdictDeny, ErrSimNotInitialized
	}
	t.withLock(func() { v, err = t.suspendV, t.suspendErr })
	if err != nil {
		return security.VerdictDeny, err
	}
	return v.Normalize(), nil
}

// WithRawTerminal 在同步作用域内借出带失效哨兵的 TerminalHandle，退出时关闭 ResizeEvents。
//
//xops:syncclosure
//xops:borrowed
func (t *SimTerminalPort) WithRawTerminal(ctx context.Context, fn func(term ports.TerminalHandle) error) error {
	if err := t.checkFn(ctx, fn != nil, "term.raw"); err != nil {
		return err
	}
	sz, err := t.Size()
	if err != nil {
		return err
	}
	resizeCh := make(chan ports.TerminalSize, 4)
	h := &simTerminalHandle{size: sz, resizeCh: resizeCh, valid: true}
	defer func() { h.expired.Store(true); close(resizeCh) }()
	return fn(h)
}

type simTerminalHandle struct {
	size     ports.TerminalSize
	resizeCh chan ports.TerminalSize
	valid    bool
	expired  atomic.Bool
}

func (h *simTerminalHandle) alive() bool                             { return h != nil && h.valid && !h.expired.Load() }
func (h *simTerminalHandle) ResizeEvents() <-chan ports.TerminalSize { return h.resizeCh }
func (h *simTerminalHandle) Read([]byte) (int, error) {
	if !h.alive() {
		return 0, ports.ErrHandleExpired
	}
	return 0, io.EOF
}
func (h *simTerminalHandle) Write(p []byte) (int, error) {
	if !h.alive() {
		return 0, ports.ErrHandleExpired
	}
	return len(p), nil
}
func (h *simTerminalHandle) Size() (out ports.TerminalSize, err error) {
	if !h.alive() {
		return out, ports.ErrHandleExpired
	}
	return h.size, nil
}
