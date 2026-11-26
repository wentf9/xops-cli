//go:build linux

package secretservice

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
)

// RFC 2409 Second Oakley Group (1024-bit MODP prime)，为 FreeDesktop Secret Service 规范固定素数。
const rfc2409Group2PrimeHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
	"FFFFFFFFFFFFFFFF"

const (
	dhPrimeBytes  = 128
	aes128KeySize = 16
)

type dhKeyPair struct {
	priv *big.Int
	pub  []byte
}

func dhPrime() (*big.Int, error) {
	raw, err := hex.DecodeString(rfc2409Group2PrimeHex)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(raw), nil
}

func generateDHKeyPair(rng io.Reader) (dhKeyPair, error) {
	p, err := dhPrime()
	if err != nil {
		return dhKeyPair{}, err
	}
	privBytes := make([]byte, dhPrimeBytes)
	defer clear(privBytes)
	if _, err := io.ReadFull(rng, privBytes); err != nil {
		return dhKeyPair{}, fmt.Errorf("%w: %w", ports.ErrEntropyShortRead, err)
	}
	priv := new(big.Int).SetBytes(privBytes)
	one := big.NewInt(1)
	pMinus2 := new(big.Int).Sub(p, big.NewInt(2))
	priv.Mod(priv, pMinus2)
	priv.Add(priv, one)
	pubInt := new(big.Int).Exp(big.NewInt(2), priv, p)
	return dhKeyPair{priv: priv, pub: pubInt.Bytes()}, nil
}

func deriveDHAES128Key(priv *big.Int, peerPubBytes []byte) ([]byte, error) {
	p, err := dhPrime()
	if err != nil {
		return nil, err
	}
	if len(peerPubBytes) == 0 || len(peerPubBytes) > dhPrimeBytes {
		return nil, fmt.Errorf("%w: DH 服务端公钥长度非法", ports.ErrCorruptData)
	}
	peerPub := new(big.Int).SetBytes(peerPubBytes)
	one := big.NewInt(1)
	pMinus1 := new(big.Int).Sub(p, one)
	if peerPub.Cmp(one) <= 0 || peerPub.Cmp(pMinus1) >= 0 {
		return nil, fmt.Errorf("%w: DH 服务端公钥落入弱子群范围", ports.ErrCorruptData)
	}
	sharedInt := new(big.Int).Exp(peerPub, priv, p)
	shared := make([]byte, dhPrimeBytes)
	sharedInt.FillBytes(shared)
	defer clear(shared)
	return hkdf.Key(sha256.New, shared, nil, "", aes128KeySize)
}

func encryptBoxAES128CBC(aesKey, iv []byte, box *secret.SecretBox) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("%w: AES-CBC IV 长度非法", ports.ErrInvalidArgument)
	}
	var cipherOut []byte
	err = box.Use(func(plain []byte) error {
		padLen := aes.BlockSize - (len(plain) % aes.BlockSize)
		padded := make([]byte, len(plain)+padLen)
		defer clear(padded)
		copy(padded, plain)
		for i := len(plain); i < len(padded); i++ {
			padded[i] = byte(padLen)
		}
		ct := make([]byte, len(padded))
		mode := cipher.NewCBCEncrypter(block, iv)
		mode.CryptBlocks(ct, padded)
		cipherOut = ct
		return nil
	})
	return cipherOut, err
}

func decryptAES128CBC(aesKey, iv, ct []byte) ([]byte, error) {
	if len(iv) != aes.BlockSize || len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%w: AES-CBC 密文或 IV 长度非法", ports.ErrCorruptData)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)
	unpadded, err := unpadPKCS7(plain)
	if err != nil {
		clear(plain)
		return nil, err
	}
	out := make([]byte, len(unpadded))
	copy(out, unpadded)
	clear(plain)
	return out, nil
}

func unpadPKCS7(b []byte) ([]byte, error) {
	if len(b) == 0 || len(b)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%w: PKCS#7 填充长度非法", ports.ErrCorruptData)
	}
	pad := int(b[len(b)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(b) {
		return nil, fmt.Errorf("%w: PKCS#7 填充字节越界", ports.ErrCorruptData)
	}
	var bad byte
	for i := len(b) - pad; i < len(b); i++ {
		bad |= b[i] ^ byte(pad)
	}
	if bad != 0 {
		return nil, fmt.Errorf("%w: PKCS#7 填充校验失败", ports.ErrCorruptData)
	}
	return b[:len(b)-pad], nil
}
