package format

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// Current is an unauthenticated publication pointer until matched to valid Meta.
type Current struct {
	VaultID    [16]byte
	Revision   uint64
	Generation uint64
	MetaHash   [32]byte
}

// MarshalBinary encodes the fixed-size publication pointer.
func (c Current) MarshalBinary() ([]byte, error) {
	if c.Revision == 0 || c.Generation == 0 {
		return nil, ErrCorrupt
	}
	b := append([]byte(nil), c.VaultID[:]...)
	b = binary.BigEndian.AppendUint64(b, c.Revision)
	b = binary.BigEndian.AppendUint64(b, c.Generation)
	b = append(b, c.MetaHash[:]...)
	return container(currentMagic, b, 0), nil
}

// ParseCurrent validates syntax, not publication authenticity or freshness.
func ParseCurrent(data []byte) (Current, error) {
	h, p, err := split(data, currentMagic, 80)
	if err != nil {
		return Current{}, err
	}
	if len(h) != 80 || len(p) != 0 {
		return Current{}, ErrCorrupt
	}
	d := decoder{b: h[prefixLen:]}
	var c Current
	copy(c.VaultID[:], d.take(16))
	c.Revision, c.Generation = d.u64(), d.u64()
	copy(c.MetaHash[:], d.take(32))
	if c.Revision == 0 || c.Generation == 0 {
		return Current{}, ErrCorrupt
	}
	return c, nil
}

// Matches binds a pointer to exact metadata; it does not authenticate the metadata.
func (c Current) Matches(data []byte, m Meta) bool {
	return c.VaultID == m.VaultID && c.Revision == m.Revision && c.Generation == m.Generation && c.MetaHash == sha256.Sum256(data)
}

// Budget is an authenticated reservation count, not an anti-rollback anchor.
type Budget struct {
	VaultID    [16]byte
	Generation uint64
	Consumed   uint64
	Sequence   uint64
	StoreID    string
}

func (b Budget) validate() error {
	if b.Generation == 0 || b.Sequence == 0 || b.Consumed > MaxEncryptions {
		return ErrCorrupt
	}
	return identifier(b.StoreID)
}

func budgetKey(b Budget, dek []byte) ([]byte, error) {
	info := lp(nil, "XOps/encrypted-file/v1/budget-mac")
	info = lp(info, b.StoreID)
	info = binary.BigEndian.AppendUint64(info, b.Generation)
	return derive(dek, b.VaultID[:], info)
}

// SealBudget authenticates a count. Durable monotonic updates remain the file layer's responsibility.
func SealBudget(b Budget, dek []byte) ([]byte, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}
	fields := binary.BigEndian.AppendUint16(nil, 1)
	fields = append(fields, b.VaultID[:]...)
	fields = binary.BigEndian.AppendUint64(fields, b.Generation)
	fields = binary.BigEndian.AppendUint64(fields, b.Consumed)
	fields = binary.BigEndian.AppendUint64(fields, b.Sequence)
	fields = lp(fields, b.StoreID)
	h := container(budgetMagic, fields, 32)
	k, err := budgetKey(b, dek)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	mac := hmac.New(sha256.New, k)
	if _, err := mac.Write(h); err != nil {
		return nil, err
	}
	return mac.Sum(h), nil
}

// OpenBudget authenticates the count and verifies the expected key identity.
func OpenBudget(data, dek []byte, vaultID [16]byte, generation uint64, storeID string) (Budget, error) {
	h, p, err := split(data, budgetMagic, 60+MaxIDBytes+32)
	if err != nil {
		return Budget{}, err
	}
	if len(p) != 32 {
		return Budget{}, ErrCorrupt
	}
	d := decoder{b: h[prefixLen:]}
	suite := d.u16()
	if d.err != nil {
		return Budget{}, d.err
	}
	if suite != 1 {
		return Budget{}, ErrUnsupported
	}
	var b Budget
	copy(b.VaultID[:], d.take(16))
	b.Generation, b.Consumed, b.Sequence = d.u64(), d.u64(), d.u64()
	b.StoreID = d.id()
	if err := d.done(); err != nil {
		return Budget{}, err
	}
	if err := b.validate(); err != nil {
		return Budget{}, err
	}
	k, err := budgetKey(b, dek)
	if err != nil {
		return Budget{}, err
	}
	defer clear(k)
	mac := hmac.New(sha256.New, k)
	if _, err := mac.Write(h); err != nil {
		return Budget{}, err
	}
	if !hmac.Equal(p, mac.Sum(nil)) {
		return Budget{}, ErrCorrupt
	}
	if b.VaultID != vaultID || b.Generation != generation || b.StoreID != storeID {
		return Budget{}, ErrIdentity
	}
	return b, nil
}
