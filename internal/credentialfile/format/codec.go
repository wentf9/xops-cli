// Package format implements the frozen v1 offline-vault binary formats.
// It performs no file I/O, prompting, KDF work or persistence. Callers must reserve
// nonce budgets and manage key lifetimes before using encryption primitives.
package format

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/wentf9/xops-cli/pkg/credential"
)

const (
	// Version identifies the frozen v1 container layout. Incompatible layouts
	// require a new version; existing suite identifiers must not be reassigned.
	Version = 1
	// MaxIDBytes bounds each identifier without changing other stores' contracts.
	MaxIDBytes = 1024
	// MaxSecretBytes bounds the plaintext of a single item.
	MaxSecretBytes = 64 * 1024
	// MaxMetaBytes bounds an entire wrapped-key container.
	MaxMetaBytes = 4096
	// MaxItemBytes includes the largest header and authentication tag.
	MaxItemBytes = 67667
	// MaxEncryptions counts reserved encryptions, including unsuccessful writes.
	MaxEncryptions = 1 << 20
	// WarningEncryptions is ceil(90% of MaxEncryptions).
	WarningEncryptions = 943719
	prefixLen          = 16
	metaMagic          = "XOPSMETA"
	itemMagic          = "XOPSITEM"
	currentMagic       = "XOPSCURR"
	budgetMagic        = "XOPSBUDG"
)

var (
	// ErrCorrupt indicates malformed or unauthentic data, without echoing input.
	ErrCorrupt = errors.New("offline credential data is corrupt")
	// ErrUnsupported indicates an unknown version or suite.
	ErrUnsupported = errors.New("offline credential format is unsupported")
	// ErrIdentity indicates a mismatch with the caller's expected identity.
	ErrIdentity = errors.New("offline credential identity mismatch")
)

type decoder struct {
	b   []byte
	err error
}

func (d *decoder) take(n int) []byte {
	if d.err != nil {
		return nil
	}
	if n < 0 || n > len(d.b) {
		d.err = ErrCorrupt
		return nil
	}
	v := d.b[:n]
	d.b = d.b[n:]
	return v
}

func (d *decoder) u8() uint8 {
	b := d.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (d *decoder) u16() uint16 {
	b := d.take(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (d *decoder) u32() uint32 {
	b := d.take(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

func (d *decoder) u64() uint64 {
	b := d.take(8)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

func (d *decoder) id() string {
	n := int(d.u16())
	if n > MaxIDBytes {
		d.err = ErrCorrupt
		return ""
	}
	return string(d.take(n))
}

func (d *decoder) done() error {
	if d.err != nil {
		return d.err
	}
	if len(d.b) != 0 {
		return ErrCorrupt
	}
	return nil
}

func identifier(s string) error {
	if len(s) == 0 || len(s) > MaxIDBytes {
		return ErrCorrupt
	}
	if err := (credential.Ref{StoreID: s, ItemID: "item"}).Validate(); err != nil {
		return fmt.Errorf("validate identifier: %w", ErrCorrupt)
	}
	return nil
}

func lp(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}

func container(magic string, fields []byte, payloadLen int) []byte {
	b := make([]byte, 0, prefixLen+len(fields))
	b = append(b, magic...)
	b = binary.BigEndian.AppendUint16(b, Version)
	b = binary.BigEndian.AppendUint16(b, uint16(prefixLen+len(fields)))
	b = binary.BigEndian.AppendUint32(b, uint32(payloadLen))
	return append(b, fields...)
}

func split(b []byte, magic string, maxBytes int) (header, payload []byte, err error) {
	if len(b) < prefixLen || len(b) > maxBytes {
		return nil, nil, ErrCorrupt
	}
	if string(b[:8]) != magic {
		return nil, nil, ErrCorrupt
	}
	if binary.BigEndian.Uint16(b[8:10]) != Version {
		return nil, nil, ErrUnsupported
	}
	h := int(binary.BigEndian.Uint16(b[10:12]))
	p := uint64(binary.BigEndian.Uint32(b[12:16]))
	if h < prefixLen || h > len(b) || p != uint64(len(b)-h) {
		return nil, nil, ErrCorrupt
	}
	return b[:h], b[h:], nil
}
