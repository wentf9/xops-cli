package mcpserver

import (
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

type errorCloser struct {
	err error
}

func (c errorCloser) Close() error {
	return c.err
}

func TestServeRequiresConfigProvider(t *testing.T) {
	err := Serve(t.Context())
	if err == nil {
		t.Fatal("expected missing config provider error")
	}
	if !strings.Contains(err.Error(), "config provider is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServeRejectsInvalidGuardrailConfigBeforeStartup(t *testing.T) {
	provider := config.NewProviderWithoutOpenSSH(&config.Configuration{
		Guardrail: &config.GuardrailConfig{BlockedPatterns: []string{"["}},
	})
	err := Serve(t.Context(), WithConfigProvider(provider))
	if err == nil || !strings.Contains(err.Error(), "validate mcp guardrail config failed") {
		t.Fatalf("expected guardrail validation error, got %v", err)
	}
	mcpMu.RLock()
	defer mcpMu.RUnlock()
	if mcpConnector != nil || mcpProvider != nil {
		t.Fatal("invalid guardrail config initialized global MCP state")
	}
}

func TestJoinCloseErrorPreservesPrimaryAndCloseErrors(t *testing.T) {
	primaryErr := errors.New("operation failed")
	closeErr := errors.New("close failed")
	err := primaryErr

	joinCloseError(&err, errorCloser{err: closeErr}, "test resource")

	if !errors.Is(err, primaryErr) || !errors.Is(err, closeErr) {
		t.Fatalf("expected both errors to be preserved, got %v", err)
	}
}

func TestFormatMCPError(t *testing.T) {
	err := FormatMCPError(ssh.ErrInteractionRequired)
	if err == nil {
		t.Fatal("expected formatted error, got nil")
	}
	if !errors.Is(err, ssh.ErrInteractionRequired) {
		t.Fatalf("expected wrapped ErrInteractionRequired, got: %v", err)
	}
	if !strings.Contains(err.Error(), "prompts are disabled in MCP mode") {
		t.Fatalf("expected clear prompt disabled message, got: %v", err)
	}

	otherErr := errors.New("other error")
	if !errors.Is(FormatMCPError(otherErr), otherErr) {
		t.Fatalf("expected other error to be preserved, got: %v", FormatMCPError(otherErr))
	}
	if FormatMCPError(nil) != nil {
		t.Fatal("expected nil for nil error")
	}
}
