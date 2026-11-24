package security

import (
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
)

// canonicalEncoder 提供零反射、带显式长度前缀与域分离标签的规范哈希编码器，保证编码单射无碰撞。
type canonicalEncoder struct {
	w   io.Writer
	err error
}

func digestCanonical(writeFn func(io.Writer) error) (Digest, error) {
	h := sha256.New()
	if err := writeFn(h); err != nil {
		return Digest{}, err
	}
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return DigestFromSHA256(sum), nil
}

func (e *canonicalEncoder) writeRaw(p []byte) {
	if e.err == nil && len(p) > 0 {
		_, e.err = e.w.Write(p)
	}
}

func (e *canonicalEncoder) writeUint8(v uint8) { e.writeRaw([]byte{v}) }
func (e *canonicalEncoder) writeInt64(v int64) { e.writeUint64(uint64(v)) }
func (e *canonicalEncoder) writeUint64(v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	e.writeRaw(buf[:])
}

func (e *canonicalEncoder) writeBytes(p []byte) { e.writeUint64(uint64(len(p))); e.writeRaw(p) }
func (e *canonicalEncoder) writeString(s string) {
	e.writeUint64(uint64(len(s)))
	e.writeRaw([]byte(s))
}

func (e *canonicalEncoder) writeStrings(items []string) {
	e.writeUint64(uint64(len(items)))
	for _, item := range items {
		e.writeString(item)
	}
}

func (e *canonicalEncoder) writeOpt(ok, valid bool, invalidErr error, write func()) {
	if !ok {
		e.writeUint8(0)
		return
	}
	if !valid {
		e.fail(invalidErr)
		return
	}
	e.writeUint8(1)
	write()
}

func (e *canonicalEncoder) writeOptEndpoint(opt algebraic.Option[netaddr.Endpoint]) {
	ep, ok := opt.Get()
	e.writeOpt(ok, ep.IsValid(), ErrInvalidOperationBinding, func() { e.writeString(ep.String()) })
}

func (e *canonicalEncoder) writeOptDigest(opt algebraic.Option[Digest]) {
	d, ok := opt.Get()
	sum, valid := d.Bytes()
	e.writeOpt(ok, valid, ErrInvalidDigest, func() { e.writeBytes(sum[:]) })
}

func (e *canonicalEncoder) writeParams(params []bindingParam) {
	e.writeUint64(uint64(len(params)))
	for _, kv := range params {
		e.writeString(kv.key)
		e.writeString(kv.value)
	}
}

func (e *canonicalEncoder) writeDecision(d GuardrailDecision) error {
	if d == nil || !d.IsValid() {
		e.fail(ErrInvalidDecision)
		return ErrInvalidDecision
	}
	switch v := d.(type) {
	case *DecisionDeny:
		e.writeUint8(uint8(DecisionKindDeny))
		e.writeString(v.code)
		e.writeString(v.reason)
	case *DecisionNeedApproval:
		e.writeUint8(uint8(DecisionKindNeedApproval))
		e.writeUint8(uint8(v.risk))
		e.writeString(v.reason)
	case *DecisionAllow:
		e.writeUint8(uint8(DecisionKindAllow))
		e.writeString(v.reason)
	default:
		e.fail(ErrInvalidDecision)
		return ErrInvalidDecision
	}
	return e.err
}

func (e *canonicalEncoder) fail(err error) {
	if err != nil && e.err == nil {
		e.err = err
	}
}
