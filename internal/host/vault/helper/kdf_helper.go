package helper

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/i18n"
	"golang.org/x/crypto/argon2"
)

const (
	kdfReqMagic         = "XOPSKDF2"
	kdfRespMagic        = "XOPSKDR2"
	kdfFrameVersion     = uint16(2)
	kdfReqHeaderBytes   = 44 // 8 magic + 2 ver + 4 totalLen + 4 time + 4 memKiB + 1 threads + 1 keyLen + 16 salt + 2 pwdLen + 2 reserved
	kdfRespHeaderBytes  = 17 // 8 magic + 2 ver + 4 totalLen + 1 status + 2 keyLen
	kdfMaxRequestBytes  = 2048
	kdfMaxResponseBytes = 256
	kdfMaxPasswordBytes = 1024
	kdfDerivedKeyBytes  = 32
	kdfSaltBytes        = 16
	kdfStatusOK         = byte(0)
	kdfStatusInvalid    = byte(1)
	kdfStatusInternal   = byte(2)
)

// Argon2idParams 描述 Argon2id 密钥派生算法参数（默认值 3 轮 / 64 MiB / 1 线程 / 32B 密钥）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type Argon2idParams struct {
	timeCost  uint32
	memoryKiB uint32
	threads   uint8
	valid     bool
}

// DefaultArgon2idParams 返回面向生产离线凭据库的安全 Argon2id 参数（time=3, memory=64 MiB, threads=1）。
func DefaultArgon2idParams() Argon2idParams {
	return Argon2idParams{timeCost: 3, memoryKiB: 64 * 1024, threads: 1, valid: true}
}

// NewArgon2idParams 校验安全下限并构造不可变 Argon2idParams（允许测试选用低内存参数加速单测）。
func NewArgon2idParams(timeCost, memoryKiB uint32, threads uint8) (Argon2idParams, error) {
	if timeCost == 0 || timeCost > 64 || memoryKiB < 64 || memoryKiB > 1024*1024 || threads == 0 || threads > 16 {
		return Argon2idParams{}, i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostVaultKDFParamsInvalid, i18n.Uint64("time", uint64(timeCost)), i18n.Uint64("memory_kib", uint64(memoryKiB)), i18n.Int("threads", int(threads)))
	}
	return Argon2idParams{timeCost: timeCost, memoryKiB: memoryKiB, threads: threads, valid: true}, nil
}

func (p Argon2idParams) IsValid() bool {
	return p.valid && p.timeCost > 0 && p.memoryKiB >= 64 && p.threads > 0
}
func (p Argon2idParams) TimeCost() uint32  { return p.timeCost }
func (p Argon2idParams) MemoryKiB() uint32 { return p.memoryKiB }
func (p Argon2idParams) Threads() uint8    { return p.threads }

// DeriveArgon2idSubprocess 通过注入的 ports.ProcessPort 以隔离二进制帧协议在子进程中执行 Argon2id 派生，
// 防止大内存 KDF 驻留或污染主进程堆空间；请求与响应帧在返回前无条件 clear 零化。
func DeriveArgon2idSubprocess(
	ctx context.Context,
	proc ports.ProcessPort,
	spec ports.ProcessSpec,
	params Argon2idParams,
	salt [kdfSaltBytes]byte,
	//xops:borrowed
	pass *secret.SecretBox,
) ([kdfDerivedKeyBytes]byte, error) {
	var zero [kdfDerivedKeyBytes]byte
	if err := checkKDFSubprocessArgs(ctx, proc, spec, params, pass); err != nil {
		return zero, err
	}
	var res ports.ProcessResult
	err := pass.Use(func(plain []byte) error {
		if len(plain) == 0 || len(plain) > kdfMaxPasswordBytes {
			return i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostInvalidField, i18n.Str("field", "passphrase"))
		}
		hdr := buildKDFRequestHeader(params, salt, len(plain))
		frame := make([]byte, kdfReqHeaderBytes+len(plain))
		defer clear(frame)
		copy(frame, hdr[:])
		copy(frame[kdfReqHeaderBytes:], plain)
		var runErr error
		res, runErr = proc.Run(ctx, spec, bytes.NewReader(frame))
		return runErr
	})
	if err != nil {
		return zero, err
	}
	if !res.IsValid() || res.Truncated() || !res.Succeeded() {
		return zero, i18n.EF(ErrProtocol, i18n.KeyHostVaultKDFSubprocessFailed)
	}
	out := res.Stdout()
	defer clear(out)
	return parseKDFResponse(out)
}

func checkKDFSubprocessArgs(ctx context.Context, proc ports.ProcessPort, spec ports.ProcessSpec, params Argon2idParams, pass *secret.SecretBox) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if proc == nil || !spec.IsValid() || !params.IsValid() || !pass.IsValid() {
		return i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostInvalidField, i18n.Str("field", "kdf_subprocess_args"))
	}
	return nil
}

// ServeArgon2idWorker 执行隔离 KDF Worker 进程单次请求处理：从 r 读取有界二进制请求帧，
// 运行 Argon2id 派生后将结果帧写入 w，并在退出前零化口令与派生密钥缓冲。
func ServeArgon2idWorker(r io.Reader, w io.Writer) error {
	if r == nil || w == nil {
		return i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostNilDependency, i18n.Str("field", "r/w"))
	}
	raw, err := io.ReadAll(io.LimitReader(r, kdfMaxRequestBytes+1))
	defer clear(raw)
	if err != nil {
		return err
	}
	if len(raw) > kdfMaxRequestBytes {
		return writeKDFResponse(w, kdfStatusInvalid, nil)
	}
	params, salt, pwd, err := parseKDFRequest(raw)
	defer clear(pwd)
	if err != nil {
		return writeKDFResponse(w, kdfStatusInvalid, nil)
	}
	dk := argon2.IDKey(pwd, salt[:], params.timeCost, params.memoryKiB, params.threads, kdfDerivedKeyBytes)
	defer clear(dk)
	return writeKDFResponse(w, kdfStatusOK, dk)
}

func buildKDFRequestHeader(params Argon2idParams, salt [kdfSaltBytes]byte, pwdLen int) [kdfReqHeaderBytes]byte {
	var b [kdfReqHeaderBytes]byte
	total := kdfReqHeaderBytes + pwdLen
	copy(b[0:8], kdfReqMagic)
	binary.BigEndian.PutUint16(b[8:10], kdfFrameVersion)
	binary.BigEndian.PutUint32(b[10:14], uint32(total))
	binary.BigEndian.PutUint32(b[14:18], params.timeCost)
	binary.BigEndian.PutUint32(b[18:22], params.memoryKiB)
	b[22] = params.threads
	b[23] = kdfDerivedKeyBytes
	copy(b[24:40], salt[:])
	binary.BigEndian.PutUint16(b[40:42], uint16(pwdLen))
	return b
}

func parseKDFRequest(b []byte) (Argon2idParams, [kdfSaltBytes]byte, []byte, error) {
	var salt [kdfSaltBytes]byte
	if len(b) < kdfReqHeaderBytes || len(b) > kdfMaxRequestBytes {
		return Argon2idParams{}, salt, nil, ErrProtocol
	}
	if string(b[0:8]) != kdfReqMagic || binary.BigEndian.Uint16(b[8:10]) != kdfFrameVersion {
		return Argon2idParams{}, salt, nil, ErrProtocol
	}
	if binary.BigEndian.Uint32(b[10:14]) != uint32(len(b)) || b[23] != kdfDerivedKeyBytes || b[42] != 0 || b[43] != 0 {
		return Argon2idParams{}, salt, nil, ErrProtocol
	}
	params, err := NewArgon2idParams(binary.BigEndian.Uint32(b[14:18]), binary.BigEndian.Uint32(b[18:22]), b[22])
	if err != nil {
		return Argon2idParams{}, salt, nil, ErrProtocol
	}
	pwdLen := int(binary.BigEndian.Uint16(b[40:42]))
	if pwdLen == 0 || pwdLen > kdfMaxPasswordBytes || kdfReqHeaderBytes+pwdLen != len(b) {
		return Argon2idParams{}, salt, nil, ErrProtocol
	}
	copy(salt[:], b[24:40])
	pwd := make([]byte, pwdLen)
	copy(pwd, b[44:])
	return params, salt, pwd, nil
}

func writeKDFResponse(w io.Writer, status byte, key []byte) error {
	total := kdfRespHeaderBytes + len(key)
	b := make([]byte, total)
	defer clear(b)
	copy(b[0:8], kdfRespMagic)
	binary.BigEndian.PutUint16(b[8:10], kdfFrameVersion)
	binary.BigEndian.PutUint32(b[10:14], uint32(total))
	b[14] = status
	binary.BigEndian.PutUint16(b[15:17], uint16(len(key)))
	copy(b[17:], key)
	_, err := w.Write(b)
	return err
}

func parseKDFResponse(b []byte) ([kdfDerivedKeyBytes]byte, error) {
	var key [kdfDerivedKeyBytes]byte
	if len(b) < kdfRespHeaderBytes || len(b) > kdfMaxResponseBytes {
		return key, ErrProtocol
	}
	if string(b[0:8]) != kdfRespMagic || binary.BigEndian.Uint16(b[8:10]) != kdfFrameVersion {
		return key, ErrProtocol
	}
	if binary.BigEndian.Uint32(b[10:14]) != uint32(len(b)) || b[14] != kdfStatusOK {
		return key, ErrProtocol
	}
	keyLen := int(binary.BigEndian.Uint16(b[15:17]))
	if keyLen != kdfDerivedKeyBytes || kdfRespHeaderBytes+keyLen != len(b) {
		return key, ErrProtocol
	}
	copy(key[:], b[17:])
	return key, nil
}
