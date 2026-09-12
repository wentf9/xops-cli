package format

import (
	"encoding/binary"
	"fmt"

	"github.com/wentf9/xops-cli/pkg/credential"
)

// WrapSuite selects a fixed approved wrapping algorithm and parameter set.
type WrapSuite uint16

const (
	// WrapPassword selects Argon2id v0x13 with 64 MiB, t=3, p=1.
	WrapPassword WrapSuite = 1
	// WrapKeyFile selects HKDF-SHA-256 of a 32-byte key file.
	WrapKeyFile WrapSuite = 2
)

// Meta contains public wrapping metadata. Parsed metadata is not authenticated.
type Meta struct {
	Suite      WrapSuite
	VaultID    [16]byte
	Generation uint64
	Revision   uint64
	Salt       []byte
	Nonce      [12]byte
	StoreID    string
}

func (m Meta) validate() error {
	if m.Suite != WrapPassword && m.Suite != WrapKeyFile {
		return ErrUnsupported
	}
	n := 16
	if m.Suite == WrapKeyFile {
		n = 32
	}
	if len(m.Salt) != n || m.Generation == 0 || m.Revision == 0 {
		return ErrCorrupt
	}
	return identifier(m.StoreID)
}

func metaHeader(m Meta) ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	b := binary.BigEndian.AppendUint16(nil, uint16(m.Suite))
	b = binary.BigEndian.AppendUint16(b, 1)
	b = append(b, m.VaultID[:]...)
	b = binary.BigEndian.AppendUint64(b, m.Generation)
	b = binary.BigEndian.AppendUint64(b, m.Revision)
	var memory, iterations uint32
	var parallel uint8
	if m.Suite == WrapPassword {
		memory, iterations, parallel = 65536, 3, 1
	}
	b = binary.BigEndian.AppendUint32(b, memory)
	b = binary.BigEndian.AppendUint32(b, iterations)
	b = append(b, parallel, byte(len(m.Salt)))
	b = append(b, m.Salt...)
	b = append(b, m.Nonce[:]...)
	b = lp(b, m.StoreID)
	return container(metaMagic, b, 48), nil
}

// ParseMeta validates the bounded format before any expensive derivation.
// It returns independent public metadata; callers must authenticate with OpenMeta.
func ParseMeta(data []byte) (Meta, error) {
	h, p, err := split(data, metaMagic, MaxMetaBytes)
	if err != nil {
		return Meta{}, err
	}
	if len(p) != 48 {
		return Meta{}, ErrCorrupt
	}
	d := decoder{b: h[prefixLen:]}
	m := Meta{Suite: WrapSuite(d.u16())}
	itemSuite := d.u16()
	if d.err != nil {
		return Meta{}, d.err
	}
	if itemSuite != 1 {
		return Meta{}, ErrUnsupported
	}
	copy(m.VaultID[:], d.take(16))
	m.Generation, m.Revision = d.u64(), d.u64()
	memory, iterations, parallel := d.u32(), d.u32(), d.u8()
	saltLen := int(d.u8())
	if saltLen != 16 && saltLen != 32 {
		return Meta{}, ErrCorrupt
	}
	m.Salt = append([]byte(nil), d.take(saltLen)...)
	copy(m.Nonce[:], d.take(12))
	m.StoreID = d.id()
	if err := d.done(); err != nil {
		return Meta{}, err
	}
	if err := m.validate(); err != nil {
		return Meta{}, err
	}
	if !validParameters(m.Suite, memory, iterations, parallel) {
		return Meta{}, ErrUnsupported
	}
	return m, nil
}

func validParameters(s WrapSuite, memory, iterations uint32, parallel uint8) bool {
	if s == WrapPassword {
		return memory == 65536 && iterations == 3 && parallel == 1
	}
	return s == WrapKeyFile && memory == 0 && iterations == 0 && parallel == 0
}

// KeyFileWrappingKey derives the wrapping key from an independent key file.
// The caller must clear the result and must never reuse a salt for new wrapping.
func KeyFileWrappingKey(m Meta, key []byte) ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	if m.Suite != WrapKeyFile {
		return nil, ErrUnsupported
	}
	info := lp(nil, "XOps/encrypted-file/v1/key-file-wrap")
	info = append(info, m.VaultID[:]...)
	info = lp(info, m.StoreID)
	return derive(key, m.Salt, info)
}

// SealMeta wraps a DEK using a prepared header and wrapping key. This low-level
// primitive requires a fresh salt, nonce and one-use wrapping key from its caller.
func SealMeta(m Meta, wrappingKey, dek []byte) ([]byte, error) {
	if len(dek) != 32 {
		return nil, ErrCorrupt
	}
	h, err := metaHeader(m)
	if err != nil {
		return nil, err
	}
	a, err := aead(wrappingKey)
	if err != nil {
		return nil, err
	}
	return a.Seal(h, m.Nonce[:], dek, h), nil
}

// OpenMeta authenticates the wrapping container and expected store identity.
// Authentication failure deliberately does not distinguish bad keys from tampering.
func OpenMeta(data, wrappingKey []byte, storeID string) (Meta, []byte, error) {
	m, err := ParseMeta(data)
	if err != nil {
		return Meta{}, nil, err
	}
	a, err := aead(wrappingKey)
	if err != nil {
		return Meta{}, nil, err
	}
	h, p, err := split(data, metaMagic, MaxMetaBytes)
	if err != nil {
		return Meta{}, nil, err
	}
	dek, err := a.Open(nil, m.Nonce[:], p, h)
	if err != nil {
		return Meta{}, nil, fmt.Errorf("authenticate wrapping: %w", credential.ErrCredentialStoreLocked)
	}
	if m.StoreID != storeID {
		clear(dek)
		return Meta{}, nil, ErrIdentity
	}
	return m, dek, nil
}
