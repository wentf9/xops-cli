package trace

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestNewLeaseScopeValidationAndAccessors(t *testing.T) {
	invalidPairs := [][2]string{
		{"", "lease-1"},
		{"pool", ""},
		{"bad domain", "lease-1"},
		{"pool", "bad\tlease"},
		{strings.Repeat("d", maxTokenLen+1), "lease-1"},
		{"pool", strings.Repeat("l", maxTokenLen+1)},
	}
	for i, pair := range invalidPairs {
		if _, err := NewLeaseScope(pair[0], pair[1]); !errors.Is(err, ErrInvalidLeaseScope) {
			t.Fatalf("case %d (%q, %q): err = %v, want ErrInvalidLeaseScope", i, pair[0], pair[1], err)
		}
	}

	var zero LeaseScope
	if zero.IsValid() || zero.Domain() != "" || zero.LeaseID() != "" {
		t.Fatal("zero LeaseScope must be invalid with empty accessors")
	}

	s1, err := NewLeaseScope("ssh-pool", "lease-01")
	if err != nil {
		t.Fatalf("NewLeaseScope failed: %v", err)
	}
	s2, err := NewLeaseScope("ssh-pool", "lease-01")
	if err != nil {
		t.Fatalf("NewLeaseScope failed: %v", err)
	}
	s3, err := NewLeaseScope("ssh-pool", "lease-02")
	if err != nil {
		t.Fatalf("NewLeaseScope failed: %v", err)
	}
	if !s1.IsValid() || s1.Domain() != "ssh-pool" || s1.LeaseID() != "lease-01" {
		t.Fatalf("unexpected scope accessors: %+v", s1)
	}
	if !s1.Equal(s2) || s1.Equal(s3) || s1.Equal(zero) {
		t.Fatal("LeaseScope.Equal mismatch")
	}
}

func TestLeaseScopeNilAndInvalidFailClosed(t *testing.T) {
	var nilCtx context.Context
	scope1, err := NewLeaseScope("pool", "lease-A")
	if err != nil {
		t.Fatalf("NewLeaseScope failed: %v", err)
	}

	if _, err := WithLeaseScope(nilCtx, scope1); !errors.Is(err, ErrNilContext) {
		t.Fatalf("WithLeaseScope(nil) error = %v, want ErrNilContext", err)
	}
	if _, err := WithLeaseScope(context.Background(), LeaseScope{}); !errors.Is(err, ErrInvalidLeaseScope) {
		t.Fatalf("WithLeaseScope(zero) error = %v, want ErrInvalidLeaseScope", err)
	}
	if err := CheckNonReentrant(nilCtx); !errors.Is(err, ErrNilContext) {
		t.Fatalf("CheckNonReentrant(nil) error = %v, want ErrNilContext", err)
	}
	if InLeaseScope(nilCtx) {
		t.Fatal("InLeaseScope(nil) must return false")
	}
	if _, ok := LeaseScopeFromContext(nilCtx); ok {
		t.Fatal("LeaseScopeFromContext(nil) must return false")
	}
}

func TestLeaseScopeAntiReentrancyAndIsolation(t *testing.T) {
	scope1, err := NewLeaseScope("pool", "lease-A")
	if err != nil {
		t.Fatalf("NewLeaseScope failed: %v", err)
	}
	scope2, err := NewLeaseScope("pool", "lease-B")
	if err != nil {
		t.Fatalf("NewLeaseScope failed: %v", err)
	}

	baseCtx := context.Background()
	if err := CheckNonReentrant(baseCtx); err != nil {
		t.Fatalf("CheckNonReentrant(base) error = %v, want nil", err)
	}
	if InLeaseScope(baseCtx) {
		t.Fatal("InLeaseScope(base) must return false")
	}

	scopedCtx, err := WithLeaseScope(baseCtx, scope1)
	if err != nil {
		t.Fatalf("WithLeaseScope failed: %v", err)
	}
	if !InLeaseScope(scopedCtx) {
		t.Fatal("InLeaseScope(scopedCtx) must return true")
	}
	got, ok := LeaseScopeFromContext(scopedCtx)
	if !ok || !got.Equal(scope1) {
		t.Fatalf("LeaseScopeFromContext = (%+v, %v), want %+v", got, ok, scope1)
	}

	// 同作用域或嵌套二次进入均必须触发 ErrReentrantLease 失败关闭。
	if reentrantErr := CheckNonReentrant(scopedCtx); !errors.Is(reentrantErr, ErrReentrantLease) {
		t.Fatalf("CheckNonReentrant(scopedCtx) error = %v, want ErrReentrantLease", reentrantErr)
	}
	if _, err := WithLeaseScope(scopedCtx, scope2); !errors.Is(err, ErrReentrantLease) {
		t.Fatalf("nested WithLeaseScope error = %v, want ErrReentrantLease", err)
	}
	if err := CheckNonReentrant(baseCtx); err != nil {
		t.Fatalf("baseCtx polluted: %v", err)
	}
}

func TestLeaseScopeFromContextIgnoresCorruptedZeroValue(t *testing.T) {
	corrupted := context.WithValue(context.Background(), leaseScopeCtxKey{}, LeaseScope{})
	if InLeaseScope(corrupted) {
		t.Fatal("corrupted zero LeaseScope must not be active")
	}
	if err := CheckNonReentrant(corrupted); err != nil {
		t.Fatalf("corrupted zero LeaseScope CheckNonReentrant = %v, want nil", err)
	}
}
