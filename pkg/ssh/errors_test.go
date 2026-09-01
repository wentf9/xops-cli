package ssh

import (
	"errors"
	"fmt"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
)

func TestConnectionError(t *testing.T) {
	rootErr := errors.New("network unreachable")
	connErr := &ConnectionError{
		NodeID:   "web-01",
		Address:  "192.168.1.10",
		Port:     22,
		AuthType: "password",
		Err:      rootErr,
	}

	wrapped := fmt.Errorf("operation failed: %w", connErr)

	// 测试 errors.Is 能够穿透 Unwrap
	if !errors.Is(wrapped, rootErr) {
		t.Errorf("expected errors.Is to match rootErr through ConnectionError")
	}

	// 测试 errors.As 能够解包出 ConnectionError
	var target *ConnectionError
	if !errors.As(wrapped, &target) {
		t.Fatalf("expected errors.As to match *ConnectionError")
	}
	if target.NodeID != "web-01" || target.Address != "192.168.1.10" || target.Port != 22 {
		t.Errorf("unmatched fields in ConnectionError: %+v", target)
	}

	expectedStr := `connect node "web-01" (192.168.1.10:22) via password failed: network unreachable`
	if connErr.Error() != expectedStr {
		t.Errorf("unexpected Error() string:\nwant: %s\ngot:  %s", expectedStr, connErr.Error())
	}
}

func TestHandshakeError(t *testing.T) {
	rootErr := errors.New("key exchange failed")
	hsErr := &HandshakeError{
		NodeID: "db-01",
		Err:    rootErr,
	}

	wrapped := fmt.Errorf("dial step failed: %w", hsErr)

	if !errors.Is(wrapped, rootErr) {
		t.Errorf("expected errors.Is to match rootErr through HandshakeError")
	}

	var target *HandshakeError
	if !errors.As(wrapped, &target) {
		t.Fatalf("expected errors.As to match *HandshakeError")
	}
	if target.NodeID != "db-01" {
		t.Errorf("expected nodeID 'db-01', got %q", target.NodeID)
	}
}

func TestProxyCycleError(t *testing.T) {
	cycleErr := &ProxyCycleError{
		NodeID: "node-a",
		Path:   []string{"node-a", "node-b", "node-a"},
	}

	expectedStr := `proxy jump cycle detected on node "node-a" (path: [node-a node-b node-a])`
	if cycleErr.Error() != expectedStr {
		t.Errorf("unexpected Error() string:\nwant: %s\ngot:  %s", expectedStr, cycleErr.Error())
	}

	wrapped := fmt.Errorf("route plan failed: %w", cycleErr)
	if !errors.Is(wrapped, config.ErrProxyCycle) {
		t.Errorf("expected errors.Is to match config.ErrProxyCycle")
	}
	if !errors.Is(wrapped, ErrProxyCycle) {
		t.Errorf("expected errors.Is to match ErrProxyCycle")
	}
}

func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{"HostKeyMismatch", fmt.Errorf("verify step: %w", ErrHostKeyMismatch), ErrHostKeyMismatch},
		{"PasswordRequired", fmt.Errorf("auth step: %w", ErrPasswordRequired), ErrPasswordRequired},
		{"KeyPathRequired", fmt.Errorf("auth step: %w", ErrKeyPathRequired), ErrKeyPathRequired},
		{"AgentNotAvailable", fmt.Errorf("auth step: %w", ErrAgentNotAvailable), ErrAgentNotAvailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, tt.want) {
				t.Errorf("errors.Is(%v, %v) = false, want true", tt.err, tt.want)
			}
		})
	}
}
