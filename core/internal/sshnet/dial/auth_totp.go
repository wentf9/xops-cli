package dial

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"strconv"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
)

type totpAlgorithm uint8

const (
	totpAlgoInvalid totpAlgorithm = iota
	totpAlgoSHA1
	totpAlgoSHA256
	totpAlgoSHA512
)

// computeTOTPFromVault 在同步明文闭包内按 RFC 6238 / RFC 4226 计算动态口令：
// 支持原始 Base32（容忍空格、连字符、小写与可选 '=' 填充）及标准 otpauth://totp/... URI
// （剥离 #fragment、支持查询反转义 +/%XX、拒绝重复 secret= 与非法转义、支持 SHA1/SHA256/SHA512），
// 绝不向外部或错误消息泄露种子明文（零 nolint）。
func (d *Dialer) computeTOTPFromVault(ctx context.Context, ref secret.Ref) (string, error) {
	if d.vault == nil {
		return "", fmt.Errorf("%w: TOTP 质询需要注入 SecretVault", ports.ErrAuthFailed)
	}
	now := time.Now()
	if d.clock != nil {
		now = d.clock.Now()
	}
	unixSec := now.Unix()
	if unixSec < 0 {
		return "", fmt.Errorf("%w: TOTP 时钟早于 Unix 纪元", ports.ErrAuthFailed)
	}
	var code string
	err := d.vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
		return box.Use(func(plain []byte) error {
			generated, tErr := computeTOTPFromPlainBytes(plain, unixSec)
			if tErr != nil {
				return tErr
			}
			code = generated
			return nil
		})
	})
	return code, err
}

// computeTOTPFromPlainBytes 在同步明文作用域内完成 otpauth:// 或 Base32 解码与 RFC 6238 HMAC 动态截断，
// 仅返回净化后的数字口令与不含任何明文的静态错误（零 nolint）。
//
//xops:secretuse
func computeTOTPFromPlainBytes(plain []byte, unixSec int64) (string, error) {
	raw := strings.TrimSpace(string(plain))
	if raw == "" {
		return "", fmt.Errorf("%w: TOTP 种子为空", ports.ErrAuthFailed)
	}
	if strings.HasPrefix(strings.ToLower(raw), "otpauth://") {
		return computeOTPAuthTOTP(raw, unixSec)
	}
	return decodeRawBase32AndComputeTOTP(raw, totpAlgoSHA1, defaultTOTPDigits, defaultTOTPPeriodSecond, unixSec)
}

// computeOTPAuthTOTP 解析标准 otpauth://totp URI 参数并在同作用域内完成 RFC 6238 口令计算：
// 剥离 #fragment、拒绝重复 secret= 参数与非法百分比转义，绝不向外部泄露明文。
//
//xops:secretuse
func computeOTPAuthTOTP(raw string, unixSec int64) (string, error) {
	rest := raw[len("otpauth://"):]
	restNoFrag, _, _ := strings.Cut(rest, "#")
	hostAndPath, query, hasQuery := strings.Cut(restNoFrag, "?")
	otpType, _, _ := strings.Cut(hostAndPath, "/")
	if !strings.EqualFold(otpType, "totp") || !hasQuery {
		return "", fmt.Errorf("%w: 仅支持包含查询参数的 otpauth://totp URI", ports.ErrAuthFailed)
	}
	algo := totpAlgoSHA1
	digits := defaultTOTPDigits
	period := defaultTOTPPeriodSecond
	var b32Source string
	secretCount := 0
	for pair := range strings.SplitSeq(query, "&") {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "secret":
			secretCount++
			b32Source = v
		case "algorithm":
			algo = classifyTOTPAlgorithm(v)
		case "digits":
			digits = classifyTOTPDigits(v)
		case "period":
			p, pErr := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if pErr != nil || p <= 0 {
				return "", fmt.Errorf("%w: TOTP period 参数须为正整数", ports.ErrAuthFailed)
			}
			period = p
		}
	}
	if secretCount != 1 || b32Source == "" || algo == totpAlgoInvalid || digits == 0 {
		return "", fmt.Errorf("%w: otpauth URI 缺少有效或存在重复 secret/algorithm/digits 参数", ports.ErrAuthFailed)
	}
	return decodeURIQueryAndComputeTOTP(b32Source, algo, digits, period, unixSec)
}

// decodeRawBase32AndComputeTOTP 清洗原始 Base32 种子并计算 RFC 6238 口令（零明文泄露）。
//
//xops:secretuse
func decodeRawBase32AndComputeTOTP(raw string, algo totpAlgorithm, digits int, period, unixSec int64) (string, error) {
	cleaned := make([]byte, len(raw))
	defer clear(cleaned)
	pos := 0
	for i := range len(raw) {
		c := raw[i]
		if isIgnoredBase32Char(c) {
			continue
		}
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		cleaned[pos] = c
		pos++
	}
	return decodeCleanedBase32AndCompute(cleaned[:pos], algo, digits, period, unixSec)
}

// decodeURIQueryAndComputeTOTP 反转义 otpauth URI 查询参数中的 '+' 与 '%XX'，清洗 Base32 种子并计算 RFC 6238 口令。
//
//xops:secretuse
func decodeURIQueryAndComputeTOTP(raw string, algo totpAlgorithm, digits int, period, unixSec int64) (string, error) {
	const hexTable = "0123456789abcdef0123456789ABCDEF"
	cleaned := make([]byte, len(raw))
	defer clear(cleaned)
	pos := 0
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch c {
		case '+':
			c = ' '
		case '%':
			if i+2 >= len(raw) {
				return "", fmt.Errorf("%w: otpauth secret 包含截断的百分号转义", ports.ErrAuthFailed)
			}
			hi := strings.IndexByte(hexTable, raw[i+1])
			lo := strings.IndexByte(hexTable, raw[i+2])
			if hi < 0 || lo < 0 {
				return "", fmt.Errorf("%w: otpauth secret 包含非法百分号转义", ports.ErrAuthFailed)
			}
			c = byte(((hi & 0x0f) << 4) | (lo & 0x0f))
			i += 2
		}
		if isIgnoredBase32Char(c) {
			continue
		}
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		cleaned[pos] = c
		pos++
	}
	return decodeCleanedBase32AndCompute(cleaned[:pos], algo, digits, period, unixSec)
}

func isIgnoredBase32Char(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '-' || c == '='
}

// decodeCleanedBase32AndCompute 解码已清洗的 Base32 种子、立即清零解码密钥并经标准库 HMAC 净化输出动态口令。
//
//xops:secretuse
func decodeCleanedBase32AndCompute(cleaned []byte, algo totpAlgorithm, digits int, period, unixSec int64) (string, error) {
	if len(cleaned) == 0 {
		return "", fmt.Errorf("%w: TOTP Base32 种子为空", ports.ErrAuthFailed)
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	key := make([]byte, enc.DecodedLen(len(cleaned)))
	defer clear(key)
	n, decErr := enc.Decode(key, cleaned)
	if decErr != nil || n == 0 {
		return "", fmt.Errorf("%w: TOTP Base32 密钥解码失败", ports.ErrAuthFailed)
	}
	return computeRFC6238Code(key[:n], algo, digits, period, unixSec), nil
}

// computeRFC6238Code 使用标准库 HMAC 计算 RFC 6238 动态截断口令并仅输出净化数字串。
//
//xops:secretuse
func computeRFC6238Code(key []byte, algo totpAlgorithm, digits int, period, unixSec int64) string {
	var hashCtor func() hash.Hash
	switch algo {
	case totpAlgoSHA256:
		hashCtor = sha256.New
	case totpAlgoSHA512:
		hashCtor = sha512.New
	default:
		hashCtor = sha1.New
	}
	mac := hmac.New(hashCtor, key)
	counter := uint64(unixSec / period)
	buf := [8]byte{
		byte(counter >> 56), byte(counter >> 48), byte(counter >> 40), byte(counter >> 32),
		byte(counter >> 24), byte(counter >> 16), byte(counter >> 8), byte(counter),
	}
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binCode := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return formatTOTPDigits(binCode, digits)
}

// classifyTOTPAlgorithm 将算法参数映射为编译期常量枚举（零明文回传）。
//
//xops:secretuse
func classifyTOTPAlgorithm(raw string) totpAlgorithm {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "", "SHA1":
		return totpAlgoSHA1
	case "SHA256":
		return totpAlgoSHA256
	case "SHA512":
		return totpAlgoSHA512
	default:
		return totpAlgoInvalid
	}
}

// classifyTOTPDigits 将位数参数映射为编译期常量 6..10（非法值返回 0，零明文回传）。
//
//xops:secretuse
func classifyTOTPDigits(raw string) int {
	switch strings.TrimSpace(raw) {
	case "", "6":
		return 6
	case "7":
		return 7
	case "8":
		return 8
	case "9":
		return 9
	case "10":
		return 10
	default:
		return 0
	}
}

func formatTOTPDigits(binCode uint32, digits int) string {
	switch digits {
	case 7:
		return fmt.Sprintf("%07d", uint64(binCode)%10_000_000)
	case 8:
		return fmt.Sprintf("%08d", uint64(binCode)%100_000_000)
	case 9:
		return fmt.Sprintf("%09d", uint64(binCode)%1_000_000_000)
	case 10:
		return fmt.Sprintf("%010d", uint64(binCode)%10_000_000_000)
	default:
		return fmt.Sprintf("%06d", uint64(binCode)%1_000_000)
	}
}
