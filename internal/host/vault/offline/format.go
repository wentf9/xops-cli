package offline

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	jsonv2 "encoding/json/v2"
	"slices"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/host/vault/helper"
	"github.com/wentf9/xops-cli/internal/i18n"
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
		return parsedVaultMeta{}, i18n.WrapS(ports.ErrCorruptData, err, i18n.KeyHostVaultOfflineMetaDecode)
	}
	if wire.FormatVersion != vaultFormatVersion || wire.KDF != "argon2id" {
		return parsedVaultMeta{}, i18n.EF(ports.ErrCorruptData, i18n.KeyHostVaultOfflineUnsupportedFmt)
	}
	params, err := helper.NewArgon2idParams(wire.KDFTime, wire.KDFMemoryKiB, wire.KDFThreads)
	if err != nil {
		return parsedVaultMeta{}, domi18n.WrapSentinel(ports.ErrCorruptData, err)
	}
	saltSlice, err := base64.StdEncoding.DecodeString(wire.SaltB64)
	if err != nil || len(saltSlice) != vaultSaltBytes {
		return parsedVaultMeta{}, i18n.EF(ports.ErrCorruptData, i18n.KeyHostVaultOfflineCorruptField, i18n.Str("field", "salt"))
	}
	nonce, err := base64.StdEncoding.DecodeString(wire.WrapNonceB64)
	if err != nil || len(nonce) != vaultNonceBytes {
		return parsedVaultMeta{}, i18n.EF(ports.ErrCorruptData, i18n.KeyHostVaultOfflineCorruptField, i18n.Str("field", "wrap_nonce"))
	}
	wrapped, err := base64.StdEncoding.DecodeString(wire.WrappedDEKB64)
	if err != nil || len(wrapped) < vaultDEKBytes+16 {
		return parsedVaultMeta{}, i18n.EF(ports.ErrCorruptData, i18n.KeyHostVaultOfflineCorruptField, i18n.Str("field", "wrapped_dek"))
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
		return parsedVaultItem{}, i18n.WrapS(ports.ErrCorruptData, err, i18n.KeyHostVaultOfflineItemDecode)
	}
	if wire.FormatVersion != vaultFormatVersion || wire.Ref != wantRef.String() {
		return parsedVaultItem{}, i18n.EF(ports.ErrCorruptData, i18n.KeyHostVaultOfflineCorruptField, i18n.Str("field", "ref"))
	}
	nonce, err := base64.StdEncoding.DecodeString(wire.NonceB64)
	if err != nil || len(nonce) != vaultNonceBytes {
		return parsedVaultItem{}, i18n.EF(ports.ErrCorruptData, i18n.KeyHostVaultOfflineCorruptField, i18n.Str("field", "nonce"))
	}
	ct, err := base64.StdEncoding.DecodeString(wire.CiphertextB64)
	if err != nil || len(ct) < 16 {
		return parsedVaultItem{}, i18n.EF(ports.ErrCorruptData, i18n.KeyHostVaultOfflineCorruptField, i18n.Str("field", "ciphertext"))
	}
	return parsedVaultItem{nonce: nonce, ciphertext: ct}, nil
}

func metaDest() (pathalg.LocalRootedDest, error) {
	return pathalg.ParseLocalRootedDest(vaultMetaFileName)
}

// itemDestForRef 将大小写敏感的 (store, item) 映射为固定长度纯小写十六进制 SHA-256 文件名，
// 彻底消除 Windows NTFS / macOS APFS 大小写不敏感文件系统上的条目碰撞及长路径膨胀，
// 同时 wire.Ref 与 AEAD AAD 仍严格绑定规范 ref.String()。
func itemDestForRef(ref secret.Ref) (pathalg.LocalRootedDest, pathalg.LocalRootedDest, error) {
	var zero pathalg.LocalRootedDest
	dir, err := pathalg.ParseLocalRootedDest(vaultItemsDirName)
	if err != nil {
		return zero, zero, err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(ref.Store()))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(ref.Item()))
	name := hex.EncodeToString(h.Sum(nil)) + ".enc"
	file, err := dir.JoinComponent(name)
	if err != nil {
		return zero, zero, err
	}
	return dir, file, nil
}
