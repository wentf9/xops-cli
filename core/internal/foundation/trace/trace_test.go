package trace

import (
	"context"
	"encoding"
	"errors"
	"strings"
	"testing"
)

var (
	_ encoding.TextAppender  = TraceID{}
	_ encoding.TextMarshaler = TraceID{}
	_ encoding.TextAppender  = OpID{}
	_ encoding.TextMarshaler = OpID{}
)

func TestTraceIDAndOpIDGenerationUniqueness(t *testing.T) {
	seenTraces := make(map[string]struct{}, 64)
	seenOps := make(map[string]struct{}, 64)

	for range 64 {
		tid, err := NewTraceID()
		if err != nil {
			t.Fatalf("NewTraceID failed: %v", err)
		}
		if !tid.IsValid() || len(tid.String()) != 32 {
			t.Fatalf("unexpected TraceID: %q", tid.String())
		}
		if _, dup := seenTraces[tid.String()]; dup {
			t.Fatalf("duplicate TraceID generated: %s", tid.String())
		}
		seenTraces[tid.String()] = struct{}{}

		oid, err := NewOpID()
		if err != nil {
			t.Fatalf("NewOpID failed: %v", err)
		}
		if !oid.IsValid() || len(oid.String()) != 32 {
			t.Fatalf("unexpected OpID: %q", oid.String())
		}
		if _, dup := seenOps[oid.String()]; dup {
			t.Fatalf("duplicate OpID generated: %s", oid.String())
		}
		seenOps[oid.String()] = struct{}{}
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
	tid, err := NewTraceID()
	if err != nil {
		t.Fatalf("NewTraceID failed: %v", err)
	}
	oid, err := NewOpID()
	if err != nil {
		t.Fatalf("NewOpID failed: %v", err)
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
	tid, err := NewTraceID()
	if err != nil {
		t.Fatalf("NewTraceID failed: %v", err)
	}
	oid1, err := NewOpID()
	if err != nil {
		t.Fatalf("NewOpID failed: %v", err)
	}
	oid2, err := NewOpID()
	if err != nil {
		t.Fatalf("NewOpID failed: %v", err)
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
