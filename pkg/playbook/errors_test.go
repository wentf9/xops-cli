package playbook

import (
	"errors"
	"fmt"
	"testing"
)

func TestPlaybookErrors(t *testing.T) {
	wrapped := fmt.Errorf("run error: %w", ErrNoTargets)
	if !errors.Is(wrapped, ErrNoTargets) {
		t.Errorf("expected errors.Is to match ErrNoTargets")
	}

	targetErr := &TargetNotFoundError{Target: "node-x"}
	wrappedTarget := fmt.Errorf("resolve error: %w", targetErr)

	var target *TargetNotFoundError
	if !errors.As(wrappedTarget, &target) {
		t.Fatalf("expected errors.As to match *TargetNotFoundError")
	}
	if target.Target != "node-x" {
		t.Errorf("expected Target to be 'node-x', got %q", target.Target)
	}

	if targetErr.Error() != `target "node-x" not found in inventory` {
		t.Errorf("unexpected Error() string: %s", targetErr.Error())
	}
}
