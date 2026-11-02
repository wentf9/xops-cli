package runtime

import (
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	config "github.com/wentf9/xops-cli/core/testutil/mcphost"
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
	if !strings.Contains(err.Error(), "state, gate, backend factory, and audit sink are required") {
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

func TestServerInstructionsAndToolGuidance(t *testing.T) {
	client := startStubResultRuntime(t, &stubResultBackend{})
	initRes := client.InitializeResult()
	if initRes == nil {
		t.Fatal("expected non-nil InitializeResult")
	}
	for _, want := range []string{
		"Managed SSH remote operations server",
		"always use this server's MCP tools",
		"Call 'nodes' first to discover available hosts and resolve the target 'nodeID'",
	} {
		if !strings.Contains(initRes.Instructions, want) {
			t.Fatalf("expected Instructions to contain %q, got:\n%s", want, initRes.Instructions)
		}
	}

	if strings.Contains(serverInstructions(true), "nodes, terminal, file, transfer, tunnel, gui") {
		t.Fatal("HTTP serverInstructions should not advertise stdio-only tunnel in primary tool list")
	}

	listRes, err := client.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}
	byName := make(map[string]string, len(listRes.Tools))
	for _, tool := range listRes.Tools {
		byName[tool.Name] = tool.Description
	}
	if !strings.Contains(byName["nodes"], "Call this tool first to inspect available servers and resolve the target 'nodeID'") {
		t.Fatalf("unexpected nodes description: %s", byName["nodes"])
	}
	if !strings.Contains(byName["file"], "Prefer this tool over terminal shell commands for reading, writing, patching, or listing remote files.") {
		t.Fatalf("unexpected file description: %s", byName["file"])
	}
}
