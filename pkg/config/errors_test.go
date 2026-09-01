package config

import (
	"errors"
	"fmt"
	"testing"
)

func TestSentinelErrors(t *testing.T) {
	wrapped := fmt.Errorf("lookup failed: %w", ErrNodeNotFound)
	if !errors.Is(wrapped, ErrNodeNotFound) {
		t.Errorf("expected errors.Is to match ErrNodeNotFound")
	}

	hostWrapped := fmt.Errorf("resolve host: %w", ErrHostNotFound)
	if !errors.Is(hostWrapped, ErrHostNotFound) {
		t.Errorf("expected errors.Is to match ErrHostNotFound")
	}

	identityWrapped := fmt.Errorf("resolve identity: %w", ErrIdentityNotFound)
	if !errors.Is(identityWrapped, ErrIdentityNotFound) {
		t.Errorf("expected errors.Is to match ErrIdentityNotFound")
	}

	cycleWrapped := fmt.Errorf("validate jumps: %w", ErrProxyCycle)
	if !errors.Is(cycleWrapped, ErrProxyCycle) {
		t.Errorf("expected errors.Is to match ErrProxyCycle")
	}
}
