package format

import (
	"crypto/sha256"
	"encoding/binary"
)

const (
	// MaxManifestBytes bounds one manifest block, including its header.
	MaxManifestBytes = 1 << 20
	manifestMagic    = "XOPSMANF"
	manifestHeader   = 18
)

// ManifestEntry describes a ciphertext, never a plaintext secret.
type ManifestEntry struct {
	ItemID   string
	FileSize uint32
	Hash     [32]byte
}

func (e ManifestEntry) validate() error {
	if err := identifier(e.ItemID); err != nil {
		return err
	}
	// Minimum header uses two one-byte identifiers and one byte of plaintext.
	if e.FileSize < 86 || e.FileSize > MaxItemBytes {
		return ErrCorrupt
	}
	return nil
}

// ManifestBlock is a bounded, strictly ordered chunk of a source or target snapshot.
type ManifestBlock struct {
	Index   uint32
	Entries []ManifestEntry
}

// MarshalBinary validates strict byte ordering and bounds before allocating output.
func (m ManifestBlock) MarshalBinary() ([]byte, error) {
	if m.Index >= MaxEncryptions || len(m.Entries) == 0 || len(m.Entries) > MaxEncryptions {
		return nil, ErrCorrupt
	}
	size := manifestHeader
	for at, e := range m.Entries {
		if err := e.validate(); err != nil {
			return nil, err
		}
		if at > 0 && m.Entries[at-1].ItemID >= e.ItemID {
			return nil, ErrCorrupt
		}
		size += 2 + len(e.ItemID) + 4 + 32
		if size > MaxManifestBytes {
			return nil, ErrCorrupt
		}
	}
	b := make([]byte, 0, size)
	b = append(b, manifestMagic...)
	b = binary.BigEndian.AppendUint16(b, Version)
	b = binary.BigEndian.AppendUint32(b, m.Index)
	b = binary.BigEndian.AppendUint32(b, uint32(len(m.Entries)))
	for _, e := range m.Entries {
		b = lp(b, e.ItemID)
		b = binary.BigEndian.AppendUint32(b, e.FileSize)
		b = append(b, e.Hash[:]...)
	}
	return b, nil
}

// ParseManifestBlock does not authenticate the block; verify its root via state MAC.
func ParseManifestBlock(data []byte) (ManifestBlock, error) {
	if len(data) < manifestHeader || len(data) > MaxManifestBytes {
		return ManifestBlock{}, ErrCorrupt
	}
	if string(data[:8]) != manifestMagic {
		return ManifestBlock{}, ErrCorrupt
	}
	if binary.BigEndian.Uint16(data[8:10]) != Version {
		return ManifestBlock{}, ErrUnsupported
	}
	d := decoder{b: data[10:]}
	m := ManifestBlock{Index: d.u32()}
	count := d.u32()
	if m.Index >= MaxEncryptions || count == 0 || uint64(count) > uint64(len(d.b)/39) {
		return ManifestBlock{}, ErrCorrupt
	}
	m.Entries = make([]ManifestEntry, 0, int(count))
	for range count {
		e := ManifestEntry{ItemID: d.id(), FileSize: d.u32()}
		copy(e.Hash[:], d.take(32))
		if err := d.err; err != nil {
			return ManifestBlock{}, err
		}
		if err := e.validate(); err != nil {
			return ManifestBlock{}, err
		}
		if len(m.Entries) > 0 && m.Entries[len(m.Entries)-1].ItemID >= e.ItemID {
			return ManifestBlock{}, ErrCorrupt
		}
		m.Entries = append(m.Entries, e)
	}
	if err := d.done(); err != nil {
		return ManifestBlock{}, err
	}
	return m, nil
}

// ManifestRoot hashes ordered block hashes. Callers must also validate consecutive
// block indices, cross-block ItemID ordering and the total entry count while streaming.
func ManifestRoot(hashes [][32]byte) ([32]byte, error) {
	if len(hashes) > MaxEncryptions {
		return [32]byte{}, ErrCorrupt
	}
	h := sha256.New()
	header := append([]byte("XOps/manifest/v1"), binary.BigEndian.AppendUint32(nil, uint32(len(hashes)))...)
	if _, err := h.Write(header); err != nil {
		return [32]byte{}, err
	}
	for _, blockHash := range hashes {
		if _, err := h.Write(blockHash[:]); err != nil {
			return [32]byte{}, err
		}
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result, nil
}
