package cmd

import (
	"slices"
	"testing"
)

func TestCommandTreeUsesCanonicalCommands(t *testing.T) {
	root := newRootCmd()
	initRootFlags(root)
	registerCommands(root)

	hostCmd, _, err := root.Find([]string{"host"})
	if err != nil {
		t.Fatalf("find host command: %v", err)
	}
	if hostCmd.Name() != "host" {
		t.Errorf("host command name = %q, want host", hostCmd.Name())
	}
	if !slices.Contains(hostCmd.Aliases, "inventory") {
		t.Errorf("host aliases = %v, want backward-compatible inventory alias", hostCmd.Aliases)
	}

	importCmd, _, err := root.Find([]string{"host", "import"})
	if err != nil {
		t.Fatalf("find host import command: %v", err)
	}
	if importCmd.Name() != "import" || !slices.Contains(importCmd.Aliases, "load") {
		t.Errorf("host import command = %q aliases %v", importCmd.Name(), importCmd.Aliases)
	}

	mcpServeCmd, _, err := root.Find([]string{"mcp", "serve"})
	if err != nil {
		t.Fatalf("find mcp serve command: %v", err)
	}
	if mcpServeCmd.Name() != "serve" {
		t.Errorf("mcp serve command name = %q, want serve", mcpServeCmd.Name())
	}

	legacyCmd, _, err := root.Find([]string{"loadHost"})
	if err != nil {
		t.Fatalf("find legacy loadHost command: %v", err)
	}
	if !legacyCmd.Hidden || legacyCmd.Deprecated == "" {
		t.Errorf("legacy loadHost command should be hidden and deprecated")
	}
}

func TestMCPCommandRejectsUnknownArguments(t *testing.T) {
	cmd := NewCmdMcp()
	if err := cmd.Args(cmd, []string{"unknown"}); err == nil {
		t.Fatal("mcp Args() error = nil, want unknown argument error")
	}
}
