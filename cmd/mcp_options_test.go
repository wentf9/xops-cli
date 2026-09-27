package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/mcpserver"
)

func parseMCPTestOptions(t *testing.T, args []string, cfg *config.Configuration) (string, mcpserver.HTTPOptions, error) {
	t.Helper()
	command := NewCmdMcp()
	var transport string
	var options mcpserver.HTTPOptions
	run := func(cmd *cobra.Command, _ []string) error {
		var err error
		transport, options, err = resolveMCPOptions(cmd, cfg, filepath.Join(t.TempDir(), "config.yaml"))
		return err
	}
	command.RunE = run
	for _, child := range command.Commands() {
		child.RunE = run
	}
	command.SetArgs(args)
	returnTransport := func() (string, mcpserver.HTTPOptions, error) {
		err := command.Execute()
		return transport, options, err
	}
	return returnTransport()
}

func TestMCPFlagsShareRootAndServeAndOverrideYAML(t *testing.T) {
	const token = "mcp-test-environment-token-not-production-1234"
	t.Setenv("XOPS_TEST_MCP_TOKEN", token)
	cfg := &config.Configuration{MCP: &config.MCPConfig{
		Transport: "stdio", Listen: "127.0.0.1:8090", TokenFile: "must-not-be-read", PublicURL: "https://mcp.example.test",
	}}
	for _, prefix := range [][]string{nil, {"serve"}} {
		args := append(append([]string(nil), prefix...), "--transport", "http", "--token-env", "XOPS_TEST_MCP_TOKEN", "--listen", "127.0.0.1:9000")
		transport, options, err := parseMCPTestOptions(t, args, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if transport != "http" || options.Listen != "127.0.0.1:9000" || options.Token != token || options.PublicURL != cfg.MCP.PublicURL {
			t.Fatal("CLI overrides or YAML defaults were not preserved")
		}
	}
	if cfg.MCP.Transport != "stdio" || cfg.MCP.TokenFile != "must-not-be-read" || cfg.MCP.TokenEnv != "" {
		t.Fatal("flag resolution mutated shared configuration")
	}
}

func TestMCPStdioDoesNotReadHTTPSecrets(t *testing.T) {
	cfg := &config.Configuration{MCP: &config.MCPConfig{
		Transport: "http", TokenFile: "nonexistent-token-file", BodyTimeout: "invalid-http-only-setting",
	}}
	transport, _, err := parseMCPTestOptions(t, []string{"serve", "--transport", "stdio"}, cfg)
	if err != nil || transport != "stdio" {
		t.Fatalf("stdio depended on unused HTTP settings: transport=%s err=%v", transport, err)
	}
}

func TestMCPInvalidFlagCombinations(t *testing.T) {
	for _, args := range [][]string{
		{"--transport", "sse"},
		{"serve", "--listen", "127.0.0.1:8000"},
		{"serve", "--transport", "http", "--token-env", "A", "--token-file", "B"},
		{"serve", "--transport", "http"},
	} {
		if _, _, err := parseMCPTestOptions(t, args, nil); err == nil {
			t.Fatalf("invalid flags accepted: %v", args)
		}
	}
}

func TestMCPTokenFileAndErrorsDoNotExposeContents(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "token")
	const token = "file-based-mcp-authentication-test-token-12345"
	if err := os.WriteFile(filePath, []byte(token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readMCPToken(filePath, "")
	if err != nil || got != token {
		t.Fatal("token file was not read correctly")
	}
	if err := os.WriteFile(filePath, []byte(strings.Repeat(token, 200)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readMCPToken(filePath, ""); err == nil || strings.Contains(err.Error(), token) {
		t.Fatalf("oversized token handling: %v", err)
	}
}

func TestMCPRecoveryHonorsConfiguredFileSize(t *testing.T) {
	size := int64(20 << 30)
	options := mcpserver.RecoveryOptions{}
	if err := applyMCPRecoverySettings(&options, &config.MCPConfig{MaxFileBytes: &size}); err != nil {
		t.Fatal(err)
	}
	if options.MaxFileBytes != size {
		t.Fatalf("recovery file limit = %d", options.MaxFileBytes)
	}
	for _, invalid := range []int64{0, -1, 1 << 51} {
		if err := applyMCPRecoverySettings(&options, &config.MCPConfig{MaxFileBytes: &invalid}); err == nil {
			t.Fatalf("invalid recovery limit %d accepted", invalid)
		}
	}
}
