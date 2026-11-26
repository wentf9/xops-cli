package offline

import (
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"fmt"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/host/vault/helper"
)

type vaultMetaWire struct {
	FormatVersion int      `json:"format_version"`
	KDF           string   `json:"kdf"`
	KDFTime       uint32   `json:"kdf_time"`
	KDFMemoryKiB  uint32   `json:"kdf_memory_kib"`
	KDFThreads    uint8    `json:"kdf_threads"`
	SaltB64       string   `json:"salt_b64"`
	WrapNonceB64  string   `json:"wrap_nonce_b64"`
	WrappedDEKB64 string   `json:"wrapped_dek_b64"`
	Stores        []string `json:"stores"`
}

type parsedVaultMeta struct {
	params     helper.Argon2idParams
	salt       [vaultSaltBytes]byte
	wrapNonce  []byte
	wrappedDEK []byte
	stores     []string
}

type vaultItemWire struct {
	FormatVersion int    `json:"format_version"`
	Ref           string `json:"ref"`
	NonceB64      string `json:"nonce_b64"`
	CiphertextB64 string `json:"ciphertext_b64"`
}

type parsedVaultItem struct {
	nonce      []byte
	ciphertext []byte
}

func encodeVaultMeta(m parsedVaultMeta) ([]byte, error) {
	wire := vaultMetaWire{
		FormatVersion: vaultFormatVersion,
		KDF:           "argon2id",
		KDFTime:       m.params.TimeCost(),
		KDFMemoryKiB:  m.params.MemoryKiB(),
		KDFThreads:    m.params.Threads(),
		SaltB64:       base64.StdEncoding.EncodeToString(m.salt[:]),
		WrapNonceB64:  base64.StdEncoding.EncodeToString(m.wrapNonce),
		WrappedDEKB64: base64.StdEncoding.EncodeToString(m.wrappedDEK),
		Stores:        slices.Clone(m.stores),
	}
	return jsonv2.Marshal(wire, jsonv2.Deterministic(true))
}

func decodeVaultMeta(raw []byte) (parsedVaultMeta, error) {
	var wire vaultMetaWire
	if err := jsonv2.Unmarshal(raw, &wire, jsonv2.RejectUnknownMembers(true)); err != nil {
		return parsedVaultMeta{}, fmt.Errorf("%w: 解析凭据库元数据失败: %w", ports.ErrCorruptData, err)
	}
	if wire.FormatVersion != vaultFormatVersion || wire.KDF != "argon2id" {
		return parsedVaultMeta{}, fmt.Errorf("%w: 不支持的凭据库格式版本或 KDF", ports.ErrCorruptData)
	}
	params, err := helper.NewArgon2idParams(wire.KDFTime, wire.KDFMemoryKiB, wire.KDFThreads)
	if err != nil {
		return parsedVaultMeta{}, fmt.Errorf("%w: %w", ports.ErrCorruptData, err)
	}
	saltSlice, err := base64.StdEncoding.DecodeString(wire.SaltB64)
	if err != nil || len(saltSlice) != vaultSaltBytes {
		return parsedVaultMeta{}, fmt.Errorf("%w: 凭据库盐值损坏", ports.ErrCorruptData)
	}
	nonce, err := base64.StdEncoding.DecodeString(wire.WrapNonceB64)
	if err != nil || len(nonce) != vaultNonceBytes {
		return parsedVaultMeta{}, fmt.Errorf("%w: DEK 包装随机数长度非法", ports.ErrCorruptData)
	}
	wrapped, err := base64.StdEncoding.DecodeString(wire.WrappedDEKB64)
	if err != nil || len(wrapped) < vaultDEKBytes+16 {
		return parsedVaultMeta{}, fmt.Errorf("%w: DEK 密文损坏", ports.ErrCorruptData)
	}
	var salt [vaultSaltBytes]byte
	copy(salt[:], saltSlice)
	stores := slices.Clone(wire.Stores)
	if len(stores) == 0 {
		stores = []string{defaultStoreName}
	}
	return parsedVaultMeta{
		params:     params,
		salt:       salt,
		wrapNonce:  nonce,
		wrappedDEK: wrapped,
		stores:     stores,
	}, nil
}

func encodeVaultItem(ref secret.Ref, nonce, ciphertext []byte) ([]byte, error) {
	wire := vaultItemWire{
		FormatVersion: vaultFormatVersion,
		Ref:           ref.String(),
		NonceB64:      base64.StdEncoding.EncodeToString(nonce),
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
	}
	return jsonv2.Marshal(wire, jsonv2.Deterministic(true))
}

func decodeVaultItem(raw []byte, wantRef secret.Ref) (parsedVaultItem, error) {
	var wire vaultItemWire
	if err := jsonv2.Unmarshal(raw, &wire, jsonv2.RejectUnknownMembers(true)); err != nil {
		return parsedVaultItem{}, fmt.Errorf("%w: 解析凭据条目失败: %w", ports.ErrCorruptData, err)
	}
	if wire.FormatVersion != vaultFormatVersion || wire.Ref != wantRef.String() {
		return parsedVaultItem{}, fmt.Errorf("%w: 凭据条目版本或引用标识不匹配", ports.ErrCorruptData)
	}
	nonce, err := base64.StdEncoding.DecodeString(wire.NonceB64)
	if err != nil || len(nonce) != vaultNonceBytes {
		return parsedVaultItem{}, fmt.Errorf("%w: 凭据条目随机数长度非法", ports.ErrCorruptData)
	}
	ct, err := base64.StdEncoding.DecodeString(wire.CiphertextB64)
	if err != nil || len(ct) < 16 {
		return parsedVaultItem{}, fmt.Errorf("%w: 凭据条目密文损坏", ports.ErrCorruptData)
	}
	return parsedVaultItem{nonce: nonce, ciphertext: ct}, nil
}

func metaDest() (pathalg.LocalRootedDest, error) {
	return pathalg.ParseLocalRootedDest(vaultMetaFileName)
}

func itemDestForRef(ref secret.Ref) (pathalg.LocalRootedDest, pathalg.LocalRootedDest, error) {
	var zero pathalg.LocalRootedDest
	dir, err := pathalg.ParseLocalRootedDest(vaultItemsDirName + "/" + ref.Store())
	if err != nil {
		return zero, zero, err
	}
	file, err := dir.JoinComponent(ref.Item() + ".enc")
	if err != nil {
		return zero, zero, err
	}
	return dir, file, nil
}
