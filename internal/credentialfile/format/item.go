package format

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
)

// ItemIdentity binds an item to the requested store, vault and DEK generation.
type ItemIdentity struct {
	VaultID    [16]byte
	Generation uint64
	Ref        credential.Ref
}

func (i ItemIdentity) validate() error {
	if i.Generation == 0 {
		return ErrCorrupt
	}
	if err := identifier(i.Ref.StoreID); err != nil {
		return err
	}
	return identifier(i.Ref.ItemID)
}

// ItemFilename never uses caller identifiers as filesystem path components.
func ItemFilename(itemID string) (string, error) {
	if err := identifier(itemID); err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(itemID))
	return hex.EncodeToString(h[:]) + ".enc", nil
}

func expiryFields(secret credential.Secret) (byte, int64, error) {
	if secret.ExpiresAt == nil {
		return 0, 0, nil
	}
	n := secret.ExpiresAt.UnixNano()
	if !time.Unix(0, n).Equal(*secret.ExpiresAt) {
		return 0, 0, ErrCorrupt
	}
	return 1, n, nil
}

// SealItem encrypts a secret, preserving expiry including historical expiries.
// The caller must durably reserve an encryption and supply a fresh random nonce.
// Ordinary Put must additionally reject an already-expired secret.
func SealItem(i ItemIdentity, nonce [12]byte, key []byte, secret credential.Secret) ([]byte, error) {
	if err := i.validate(); err != nil {
		return nil, err
	}
	if len(secret.Value) == 0 || len(secret.Value) > MaxSecretBytes {
		return nil, ErrCorrupt
	}
	flag, expires, err := expiryFields(secret)
	if err != nil {
		return nil, err
	}
	b := binary.BigEndian.AppendUint16(nil, 1)
	b = append(b, i.VaultID[:]...)
	b = binary.BigEndian.AppendUint64(b, i.Generation)
	b = append(b, nonce[:]...)
	b = append(b, flag)
	b = binary.BigEndian.AppendUint64(b, uint64(expires))
	b = lp(lp(b, i.Ref.StoreID), i.Ref.ItemID)
	h := container(itemMagic, b, len(secret.Value)+16)
	a, err := aead(key)
	if err != nil {
		return nil, err
	}
	return a.Seal(h, nonce[:], secret.Value, h), nil
}

type itemHeader struct {
	identity ItemIdentity
	nonce    [12]byte
	expires  *time.Time
}

func parseItemHeader(h []byte) (itemHeader, error) {
	d := decoder{b: h[prefixLen:]}
	suite := d.u16()
	if d.err != nil {
		return itemHeader{}, d.err
	}
	if suite != 1 {
		return itemHeader{}, ErrUnsupported
	}
	var out itemHeader
	copy(out.identity.VaultID[:], d.take(16))
	out.identity.Generation = d.u64()
	copy(out.nonce[:], d.take(12))
	flag, n := d.u8(), int64(d.u64())
	if flag > 1 || (flag == 0 && n != 0) {
		return itemHeader{}, ErrCorrupt
	}
	if flag == 1 {
		t := time.Unix(0, n).UTC()
		out.expires = &t
	}
	out.identity.Ref = credential.Ref{StoreID: d.id(), ItemID: d.id()}
	if err := d.done(); err != nil {
		return itemHeader{}, err
	}
	if err := out.identity.validate(); err != nil {
		return itemHeader{}, err
	}
	return out, nil
}

// OpenItem authenticates identity and expiry without imposing a wall clock.
// Maintenance can read expired data; ordinary Get must check expiry before delivery.
func OpenItem(data, key []byte, expected ItemIdentity) (credential.Secret, error) {
	if err := expected.validate(); err != nil {
		return credential.Secret{}, err
	}
	h, p, err := split(data, itemMagic, MaxItemBytes)
	if err != nil {
		return credential.Secret{}, err
	}
	if len(p) < 17 || len(p) > MaxSecretBytes+16 {
		return credential.Secret{}, ErrCorrupt
	}
	i, err := parseItemHeader(h)
	if err != nil {
		return credential.Secret{}, err
	}
	a, err := aead(key)
	if err != nil {
		return credential.Secret{}, err
	}
	value, err := a.Open(nil, i.nonce[:], p, h)
	if err != nil {
		return credential.Secret{}, ErrCorrupt
	}
	if i.identity != expected {
		clear(value)
		return credential.Secret{}, ErrIdentity
	}
	return credential.Secret{Value: value, ExpiresAt: i.expires}, nil
}
