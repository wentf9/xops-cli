package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"
	"testing"
)

func newTestCrypter(t *testing.T) *Crypter {
	t.Helper()
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	c, err := NewCrypter(key)
	if err != nil {
		t.Fatalf("NewCrypter failed: %v", err)
	}
	return c
}

func TestNewCrypter_InvalidKeySize(t *testing.T) {
	badSizes := []int{0, 1, 16, 31, 33, 64}
	for _, size := range badSizes {
		key := make([]byte, size)
		_, err := NewCrypter(key)
		if err == nil {
			t.Errorf("expected error for key size %d, got nil", size)
		}
	}
}

func TestNewCrypter_ValidKey(t *testing.T) {
	key := make([]byte, 32)
	c, err := NewCrypter(key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil Crypter")
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	c := newTestCrypter(t)

	cases := []string{
		"hello world",
		"",
		"password123!@#",
		"中文密码测试",
		strings.Repeat("a", 1024),
	}

	for _, plaintext := range cases {
		t.Run(plaintext[:min(len(plaintext), 20)], func(t *testing.T) {
			encrypted, err := c.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			decrypted, err := c.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if decrypted != plaintext {
				t.Errorf("round-trip failed: got %q, want %q", decrypted, plaintext)
			}
		})
	}
}

func TestEncrypt_ProducesPrefix(t *testing.T) {
	c := newTestCrypter(t)
	encrypted, err := c.Encrypt("test")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if !strings.HasPrefix(encrypted, Prefix) {
		t.Errorf("encrypted string should start with %q, got %q", Prefix, encrypted)
	}
}

func TestDecrypt_InvalidFormat(t *testing.T) {
	c := newTestCrypter(t)
	_, err := c.Decrypt("not-encrypted")
	if err == nil {
		t.Error("expected error for input without ENC: prefix")
	}
}

func TestDecrypt_CorruptedData(t *testing.T) {
	c := newTestCrypter(t)
	encrypted, err := c.Encrypt("test data")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// 篡改密文中间部分
	corrupted := encrypted[:len(Prefix)+5] + "XXXX" + encrypted[len(Prefix)+9:]
	_, err = c.Decrypt(corrupted)
	if err == nil {
		t.Error("expected error when decrypting corrupted data")
	}
}

func TestDecrypt_TooShort(t *testing.T) {
	c := newTestCrypter(t)
	// ENC: + 很短的 base64（解码后短于 nonce）
	_, err := c.Decrypt(Prefix + "dGVz")
	if err == nil {
		t.Error("expected error for data shorter than nonce size")
	}
}

func TestIsEncrypted(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"ENC:abc123", true},
		{"ENC:", true},
		{"enc:abc", false},
		{"plaintext", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := IsEncrypted(tt.input); got != tt.want {
				t.Errorf("IsEncrypted(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestEncrypt_SameInput_DifferentOutput(t *testing.T) {
	c := newTestCrypter(t)
	plaintext := "deterministic?"

	enc1, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("first Encrypt failed: %v", err)
	}

	enc2, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("second Encrypt failed: %v", err)
	}

	if enc1 == enc2 {
		t.Error("two encryptions of the same plaintext should produce different ciphertext (random nonce)")
	}
}

// Fixture writer for legacy ciphertext; excluded from production builds.
// Encrypt 加密字符串
// 输出格式: ENC:<Base64(Nonce + Ciphertext)>
func (c *Crypter) Encrypt(plaintext string) (string, error) {
	// 1. 生成随机 Nonce (Number used once)
	// GCM 标准 Nonce 长度为 12 字节
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// 2. 加密 (Seal)
	// Seal 会将结果追加到第一个参数 (dst) 后面，这里我们将 Nonce 作为前缀一并存储
	ciphertext := c.gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	// 3. Base64 编码并添加前缀
	return Prefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}
