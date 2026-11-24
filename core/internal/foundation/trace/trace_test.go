package trace

import (
	"bytes"
	"context"
	"encoding"
	"errors"
	"io"
	"strings"
	"testing"
)

var (
	_ encoding.TextAppender  = TraceID{}
	_ encoding.TextMarshaler = TraceID{}
	_ encoding.TextAppender  = OpID{}
	_ encoding.TextMarshaler = OpID{}
)

type failingReader struct {
	err error
}

func (r failingReader) Read([]byte) (int, error) {
	return 0, r.err
}

func deterministicEntropy(seed byte, count int) io.Reader {
	buf := make([]byte, count*randomIDBytes)
	for i := range count {
		for j := range randomIDBytes {
			buf[i*randomIDBytes+j] = seed + byte(i) + byte(j)
		}
	}
	return bytes.NewReader(buf)
}

func TestTraceIDAndOpIDFromBytesAndEntropyDeterministic(t *testing.T) {
	var raw [16]byte
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	const wantHex = "0102030405060708090a0b0c0d0e0f10"

	tid := TraceIDFromBytes(raw)
	if !tid.IsValid() || tid.String() != wantHex {
		t.Fatalf("TraceIDFromBytes = (%q, valid=%v), want %q", tid.String(), tid.IsValid(), wantHex)
	}
	oid := OpIDFromBytes(raw)
	if !oid.IsValid() || oid.String() != wantHex {
		t.Fatalf("OpIDFromBytes = (%q, valid=%v), want %q", oid.String(), oid.IsValid(), wantHex)
	}

	// 同源字节流在两次调用间必须 100% 确定性复现（保障 P2-T6 单种子 DST）。
	tidA, err := NewTraceIDFrom(bytes.NewReader(raw[:]))
	if err != nil || !tidA.Equal(tid) {
		t.Fatalf("NewTraceIDFrom = (%v, %v), want %v", tidA, err, tid)
	}
	oidA, err := NewOpIDFrom(bytes.NewReader(raw[:]))
	if err != nil || !oidA.Equal(oid) {
		t.Fatalf("NewOpIDFrom = (%v, %v), want %v", oidA, err, oid)
	}

	assertUniqueEntropyIDs(t, deterministicEntropy(1, 64), 32)
}

func assertUniqueEntropyIDs(t *testing.T, entropy io.Reader, count int) {
	t.Helper()
	seenTraces := make(map[string]struct{}, count)
	seenOps := make(map[string]struct{}, count)
	for range count {
		gTID, gErr := NewTraceIDFrom(entropy)
		if gErr != nil || !gTID.IsValid() || len(gTID.String()) != 32 {
			t.Fatalf("NewTraceIDFrom failed: (%q, %v)", gTID.String(), gErr)
		}
		assertNoDupID(t, "TraceID", seenTraces, gTID.String())

		gOID, gErr := NewOpIDFrom(entropy)
		if gErr != nil || !gOID.IsValid() || len(gOID.String()) != 32 {
			t.Fatalf("NewOpIDFrom failed: (%q, %v)", gOID.String(), gErr)
		}
		assertNoDupID(t, "OpID", seenOps, gOID.String())
	}
}

func assertNoDupID(t *testing.T, label string, seen map[string]struct{}, id string) {
	t.Helper()
	if _, dup := seen[id]; dup {
		t.Fatalf("duplicate %s: %s", label, id)
	}
	seen[id] = struct{}{}
}

func TestNewIDFromEntropyFailClosed(t *testing.T) {
	if _, err := NewTraceIDFrom(nil); !errors.Is(err, ErrNilEntropy) {
		t.Fatalf("NewTraceIDFrom(nil) error = %v, want ErrNilEntropy", err)
	}
	if _, err := NewOpIDFrom(nil); !errors.Is(err, ErrNilEntropy) {
		t.Fatalf("NewOpIDFrom(nil) error = %v, want ErrNilEntropy", err)
	}

	short := bytes.NewReader([]byte{1, 2, 3})
	if _, err := NewTraceIDFrom(short); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("NewTraceIDFrom(short) error = %v, want io.ErrUnexpectedEOF", err)
	}
	if _, err := NewOpIDFrom(bytes.NewReader([]byte{1, 2, 3})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("NewOpIDFrom(short) error = %v, want io.ErrUnexpectedEOF", err)
	}

	readBoom := errors.New("entropy device failed")
	if _, err := NewTraceIDFrom(failingReader{err: readBoom}); !errors.Is(err, readBoom) {
		t.Fatalf("NewTraceIDFrom(fail) error = %v, want readBoom", err)
	}
	if _, err := NewOpIDFrom(failingReader{err: readBoom}); !errors.Is(err, readBoom) {
		t.Fatalf("NewOpIDFrom(fail) error = %v, want readBoom", err)
	}
}

func TestParseTraceIDAndOpIDValidation(t *testing.T) {
	invalidTokens := []string{
		"",
		" ",
		"trace id",
		"trace\tid",
		"trace\nid",
		"\x00abc",
		"\x7fabc",
		"中文",
		strings.Repeat("a", maxTokenLen+1),
	}
	for _, raw := range invalidTokens {
		if _, err := ParseTraceID(raw); !errors.Is(err, ErrInvalidTraceID) {
			t.Fatalf("ParseTraceID(%q) error = %v, want ErrInvalidTraceID", raw, err)
		}
		if _, err := ParseOpID(raw); !errors.Is(err, ErrInvalidOpID) {
			t.Fatalf("ParseOpID(%q) error = %v, want ErrInvalidOpID", raw, err)
		}
	}

	validToken := strings.Repeat("x", maxTokenLen)
	tid, err := ParseTraceID(validToken)
	if err != nil || !tid.IsValid() || !tid.Equal(tid) {
		t.Fatalf("ParseTraceID(maxLen) failed: (%v, %v)", tid, err)
	}
	oid, err := ParseOpID("op-01_ABC.9")
	if err != nil || !oid.IsValid() || oid.String() != "op-01_ABC.9" {
		t.Fatalf("ParseOpID failed: (%v, %v)", oid, err)
	}
	if oid.Equal(OpID{}) {
		t.Fatal("valid OpID must not equal zero value")
	}
}

func TestZeroValueTraceIDAndOpIDFailClosed(t *testing.T) {
	var zeroTID TraceID
	if zeroTID.IsValid() || zeroTID.String() != "" {
		t.Fatal("zero TraceID must be invalid")
	}
	if _, err := zeroTID.AppendText([]byte("p:")); !errors.Is(err, ErrInvalidTraceID) {
		t.Fatalf("zero TraceID.AppendText error = %v, want ErrInvalidTraceID", err)
	}
	if _, err := zeroTID.MarshalText(); !errors.Is(err, ErrInvalidTraceID) {
		t.Fatalf("zero TraceID.MarshalText error = %v, want ErrInvalidTraceID", err)
	}

	var zeroOID OpID
	if zeroOID.IsValid() || zeroOID.String() != "" {
		t.Fatal("zero OpID must be invalid")
	}
	if _, err := zeroOID.AppendText([]byte("p:")); !errors.Is(err, ErrInvalidOpID) {
		t.Fatalf("zero OpID.AppendText error = %v, want ErrInvalidOpID", err)
	}
	if _, err := zeroOID.MarshalText(); !errors.Is(err, ErrInvalidOpID) {
		t.Fatalf("zero OpID.MarshalText error = %v, want ErrInvalidOpID", err)
	}
}

func TestValidTraceIDAndOpIDTextEncoding(t *testing.T) {
	tid, err := ParseTraceID("trace-1")
	if err != nil {
		t.Fatalf("ParseTraceID failed: %v", err)
	}
	appended, err := tid.AppendText([]byte("id="))
	if err != nil || string(appended) != "id=trace-1" {
		t.Fatalf("AppendText = (%q, %v)", appended, err)
	}
	marshaled, err := tid.MarshalText()
	if err != nil || string(marshaled) != "trace-1" {
		t.Fatalf("MarshalText = (%q, %v)", marshaled, err)
	}

	oid, err := ParseOpID("op-1")
	if err != nil {
		t.Fatalf("ParseOpID failed: %v", err)
	}
	opAppended, err := oid.AppendText([]byte("op="))
	if err != nil || string(opAppended) != "op=op-1" {
		t.Fatalf("OpID.AppendText = (%q, %v)", opAppended, err)
	}
	opMarshaled, err := oid.MarshalText()
	if err != nil || string(opMarshaled) != "op-1" {
		t.Fatalf("OpID.MarshalText = (%q, %v)", opMarshaled, err)
	}
}

func TestWithTraceFailClosed(t *testing.T) {
	var nilCtx context.Context
	entropy := deterministicEntropy(10, 2)
	tid, err := NewTraceIDFrom(entropy)
	if err != nil {
		t.Fatalf("NewTraceIDFrom failed: %v", err)
	}
	oid, err := NewOpIDFrom(entropy)
	if err != nil {
		t.Fatalf("NewOpIDFrom failed: %v", err)
	}

	if _, err := WithTrace(nilCtx, tid, oid); !errors.Is(err, ErrNilContext) {
		t.Fatalf("WithTrace(nil) error = %v, want ErrNilContext", err)
	}
	if _, err := WithTrace(context.Background(), TraceID{}, OpID{}); !errors.Is(err, ErrInvalidTraceID) {
		t.Fatalf("WithTrace(zero, zero) error = %v, want ErrInvalidTraceID", err)
	}
	if _, _, ok := TraceFromContext(nilCtx); ok {
		t.Fatal("TraceFromContext(nil) must return false")
	}
	if _, ok := TraceIDFromContext(context.Background()); ok {
		t.Fatal("empty context must have no TraceID")
	}
	if _, ok := OpIDFromContext(context.Background()); ok {
		t.Fatal("empty context must have no OpID")
	}
}

func TestWithTraceAndInheritance(t *testing.T) {
	entropy := deterministicEntropy(30, 3)
	tid, err := NewTraceIDFrom(entropy)
	if err != nil {
		t.Fatalf("NewTraceIDFrom failed: %v", err)
	}
	oid1, err := NewOpIDFrom(entropy)
	if err != nil {
		t.Fatalf("NewOpIDFrom failed: %v", err)
	}
	oid2, err := NewOpIDFrom(entropy)
	if err != nil {
		t.Fatalf("NewOpIDFrom failed: %v", err)
	}

	parentCtx, err := WithTrace(context.Background(), tid, oid1)
	if err != nil {
		t.Fatalf("WithTrace parent failed: %v", err)
	}
	gotTID, gotOID, ok := TraceFromContext(parentCtx)
	if !ok || !gotTID.Equal(tid) || !gotOID.Equal(oid1) {
		t.Fatalf("parent trace mismatch: (%v, %v, %v)", gotTID, gotOID, ok)
	}

	// 子上下文传入零值 TraceID 时，必须自动继承父级 TraceID，同时更新 OpID 且不污染父上下文。
	childCtx, err := WithTrace(parentCtx, TraceID{}, oid2)
	if err != nil {
		t.Fatalf("WithTrace child failed: %v", err)
	}
	childTID, ok := TraceIDFromContext(childCtx)
	if !ok || !childTID.Equal(tid) {
		t.Fatalf("child TraceID = (%v, %v), want %v", childTID, ok, tid)
	}
	childOID, ok := OpIDFromContext(childCtx)
	if !ok || !childOID.Equal(oid2) {
		t.Fatalf("child OpID = (%v, %v), want %v", childOID, ok, oid2)
	}
	parentOID, ok := OpIDFromContext(parentCtx)
	if !ok || !parentOID.Equal(oid1) {
		t.Fatalf("parent OpID mutated to (%v, %v), want %v", parentOID, ok, oid1)
	}
}

func TestTraceFromContextIgnoresForeignKeysAndZeroRecord(t *testing.T) {
	// 即便在白名单包内手动注入无效零值 traceRecord，读取也必须失败关闭返回 false。
	corrupted := context.WithValue(context.Background(), traceCtxKey{}, traceRecord{})
	if _, _, ok := TraceFromContext(corrupted); ok {
		t.Fatal("corrupted zero traceRecord must return false")
	}
	onlyOpCtx, err := WithTrace(context.Background(), TraceID{}, OpID{value: "op-only"})
	if err != nil {
		t.Fatalf("WithTrace(onlyOp) failed: %v", err)
	}
	if _, ok := TraceIDFromContext(onlyOpCtx); ok {
		t.Fatal("TraceIDFromContext must return false when only OpID was set")
	}
	if oid, ok := OpIDFromContext(onlyOpCtx); !ok || oid.String() != "op-only" {
		t.Fatalf("OpIDFromContext = (%v, %v), want op-only", oid, ok)
	}
}
