// Package kdfhelper defines the private, single-request KDF wire protocol.
// Linux execution uses a bounded same-binary worker before normal CLI startup.
package kdfhelper

import (
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

const (
	// MaxRequestBytes bounds the complete request before parsing or allocation.
	MaxRequestBytes = 2048
	// MaxResponseBytes bounds the complete response.
	MaxResponseBytes = 256
	requestFixed     = 48
	responseFixed    = 17
)

// ErrProtocol indicates an invalid frame without echoing potentially secret input.
var ErrProtocol = errors.New("invalid private KDF protocol frame")

// Status is a fixed, non-textual response classification.
type Status byte

const (
	// Success must also be accompanied by a successful process exit.
	Success Status = iota
	// InvalidRequest indicates malformed input.
	InvalidRequest
	// UnsupportedVersion indicates a protocol version mismatch.
	UnsupportedVersion
	// ResourceFailure indicates a reliably identified resource failure.
	ResourceFailure
	// InternalFailure indicates other helper failure.
	InternalFailure
)

// Request owns its password bytes; Zero must be called when they are no longer needed.
type Request struct {
	Salt     [16]byte
	Password []byte
}

// Zero clears the owned password, leaving only public metadata.
func (r *Request) Zero() { clear(r.Password); r.Password = nil }

func validPassword(p []byte) bool {
	if len(p) == 0 || len(p) > 1024 || !utf8.Valid(p) {
		return false
	}
	for _, b := range p {
		if b == 0 || b == '\r' || b == '\n' {
			return false
		}
	}
	return true
}

// MarshalBinary emits the fixed approved parameters; callers must clear the frame.
func (r Request) MarshalBinary() ([]byte, error) {
	if !validPassword(r.Password) {
		return nil, ErrProtocol
	}
	b := make([]byte, requestFixed+len(r.Password))
	copy(b, "XOPSKDFQ")
	binary.BigEndian.PutUint16(b[8:10], 1)
	binary.BigEndian.PutUint32(b[10:14], uint32(len(b)))
	b[14] = 1
	binary.BigEndian.PutUint32(b[15:19], 65536)
	binary.BigEndian.PutUint32(b[19:23], 3)
	b[23] = 1
	binary.BigEndian.PutUint16(b[24:26], 32)
	copy(b[26:42], r.Salt[:])
	binary.BigEndian.PutUint32(b[42:46], 0x13)
	binary.BigEndian.PutUint16(b[46:48], uint16(len(r.Password)))
	copy(b[48:], r.Password)
	return b, nil
}

// ParseRequest validates all framing and KDF parameters before copying a password.
// The transport must separately ensure EOF, a deadline and the same byte limit.
func ParseRequest(b []byte) (Request, error) {
	if len(b) < requestFixed || len(b) > MaxRequestBytes {
		return Request{}, ErrProtocol
	}
	if string(b[:8]) != "XOPSKDFQ" || binary.BigEndian.Uint16(b[8:10]) != 1 {
		return Request{}, ErrProtocol
	}
	if uint64(binary.BigEndian.Uint32(b[10:14])) != uint64(len(b)) {
		return Request{}, ErrProtocol
	}
	if !parametersValid(b) {
		return Request{}, ErrProtocol
	}
	n := int(binary.BigEndian.Uint16(b[46:48]))
	if n != len(b)-requestFixed || !validPassword(b[48:]) {
		return Request{}, ErrProtocol
	}
	r := Request{Password: append([]byte(nil), b[48:]...)}
	copy(r.Salt[:], b[26:42])
	return r, nil
}

func parametersValid(b []byte) bool {
	return b[14] == 1 && binary.BigEndian.Uint32(b[15:19]) == 65536 &&
		binary.BigEndian.Uint32(b[19:23]) == 3 && b[23] == 1 &&
		binary.BigEndian.Uint16(b[24:26]) == 32 && binary.BigEndian.Uint32(b[42:46]) == 0x13
}

// Response owns a key only on success. Process status must still be checked.
type Response struct {
	Status Status
	Key    []byte
}

// Zero clears the owned derived key.
func (r *Response) Zero() { clear(r.Key); r.Key = nil }

func (r Response) valid() bool {
	if r.Status > InternalFailure {
		return false
	}
	if r.Status == Success {
		return len(r.Key) == 32
	}
	return len(r.Key) == 0
}

// MarshalBinary emits one bounded response. The caller must clear the output.
func (r Response) MarshalBinary() ([]byte, error) {
	if !r.valid() {
		return nil, ErrProtocol
	}
	b := make([]byte, responseFixed+len(r.Key))
	copy(b, "XOPSKDFR")
	binary.BigEndian.PutUint16(b[8:10], 1)
	binary.BigEndian.PutUint32(b[10:14], uint32(len(b)))
	b[14] = byte(r.Status)
	binary.BigEndian.PutUint16(b[15:17], uint16(len(r.Key)))
	copy(b[17:], r.Key)
	return b, nil
}

// ParseResponse rejects trailing data, unknown statuses and keys on failure frames.
func ParseResponse(b []byte) (Response, error) {
	if len(b) < responseFixed || len(b) > MaxResponseBytes {
		return Response{}, ErrProtocol
	}
	if string(b[:8]) != "XOPSKDFR" || binary.BigEndian.Uint16(b[8:10]) != 1 {
		return Response{}, ErrProtocol
	}
	if uint64(binary.BigEndian.Uint32(b[10:14])) != uint64(len(b)) || int(binary.BigEndian.Uint16(b[15:17])) != len(b)-responseFixed {
		return Response{}, ErrProtocol
	}
	r := Response{Status: Status(b[14]), Key: b[17:]}
	if !r.valid() {
		return Response{}, ErrProtocol
	}
	r.Key = append([]byte(nil), r.Key...)
	return r, nil
}
