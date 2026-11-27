package sys

import (
	"crypto/rand"

	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// CryptoEntropy 实现 ports.Entropy（io.Reader），以 Go 标准库 crypto/rand 提供并发安全密码学熵源；零值恒无效。
//
//xops:opaque
//xops:failclosed
type CryptoEntropy struct {
	valid bool
}

// NewCryptoEntropy 构造可用的真实密码学熵源实例。
func NewCryptoEntropy() *CryptoEntropy { return &CryptoEntropy{valid: true} }

// Read 从操作系统密码学随机源填充 p；零值或 nil 接收者失败关闭返回 ErrInvalidArgument。
func (e *CryptoEntropy) Read(p []byte) (int, error) {
	if e == nil || !e.valid {
		return 0, i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostNotInitialized, i18n.Str("component", "CryptoEntropy"))
	}
	return rand.Read(p)
}
