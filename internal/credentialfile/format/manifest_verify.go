package format

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

// ManifestVerifier checks an entire snapshot without retaining all block hashes.
// It is single-owner, contains public metadata only, and performs no I/O.
type ManifestVerifier struct {
	hash           hash.Hash
	expectedBlocks uint32
	expectedItems  uint64
	blocks         uint32
	items          uint64
	lastID         string
	finished       bool
}

// NewManifestVerifier fixes the authenticated expected counts before reading blocks.
func NewManifestVerifier(blocks uint32, items uint64) (*ManifestVerifier, error) {
	if blocks > MaxEncryptions || items > MaxEncryptions || uint64(blocks) > items || (blocks == 0 && items != 0) {
		return nil, ErrCorrupt
	}
	h := sha256.New()
	header := append([]byte("XOps/manifest/v1"), binary.BigEndian.AppendUint32(nil, blocks)...)
	if _, err := h.Write(header); err != nil {
		return nil, err
	}
	return &ManifestVerifier{hash: h, expectedBlocks: blocks, expectedItems: items}, nil
}

// Add validates a consecutive, strictly ordered block and adds its exact-byte hash.
// Rejected blocks do not advance the verifier.
func (v *ManifestVerifier) Add(data []byte) error {
	if v == nil || v.hash == nil || v.finished || v.blocks >= v.expectedBlocks {
		return ErrCorrupt
	}
	m, err := ParseManifestBlock(data)
	if err != nil {
		return err
	}
	if m.Index != v.blocks || (v.blocks > 0 && m.Entries[0].ItemID <= v.lastID) {
		return ErrCorrupt
	}
	if uint64(len(m.Entries)) > v.expectedItems-v.items {
		return ErrCorrupt
	}
	h := sha256.Sum256(data)
	if _, err := v.hash.Write(h[:]); err != nil {
		return err
	}
	v.blocks++
	v.items += uint64(len(m.Entries))
	v.lastID = m.Entries[len(m.Entries)-1].ItemID
	return nil
}

// Finish verifies counts and the state-authenticated root. It cannot prove that
// the listed files actually exist; the file layer must authenticate those files.
func (v *ManifestVerifier) Finish(expected [32]byte) error {
	if v == nil || v.hash == nil || v.finished {
		return ErrCorrupt
	}
	v.finished = true
	if v.blocks != v.expectedBlocks || v.items != v.expectedItems {
		return ErrCorrupt
	}
	var root [32]byte
	copy(root[:], v.hash.Sum(nil))
	if root != expected {
		return ErrCorrupt
	}
	return nil
}
