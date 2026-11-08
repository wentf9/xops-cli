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
	for _, alias := range []string{"h", "hosts", "inventory", "inv"} {
		if !slices.Contains(hostCmd.Aliases, alias) {
			t.Errorf("host aliases = %v, want %q", hostCmd.Aliases, alias)
		}
	}

	importCmd, _, err := root.Find([]string{"host", "import"})
	if err != nil {
		t.Fatalf("find host import command: %v", err)
	}
	if importCmd.Name() != "import" || !slices.Contains(importCmd.Aliases, "load") || !slices.Contains(importCmd.Aliases, "imp") {
		t.Errorf("host import command = %q aliases %v", importCmd.Name(), importCmd.Aliases)
	}

	mcpServeCmd, _, err := root.Find([]string{"mcp", "serve"})
	if err != nil {
		t.Fatalf("find mcp serve command: %v", err)
	}
	if mcpServeCmd.Name() != "serve" {
		t.Errorf("mcp serve command name = %q, want serve", mcpServeCmd.Name())
	}

	if _, _, err := root.Find([]string{"loadHost"}); err == nil {
		t.Fatal("removed loadHost command is still registered")
	}

	for _, removed := range []string{"ping", "nc", "dns", "encode", "forward", "sudo", "firewall"} {
		found, _, err := root.Find([]string{removed})
		if err == nil && found != nil && found.Name() == removed {
			t.Fatalf("removed command %q is still registered", removed)
		}
	}

	// Verify concise command aliases resolve to expected canonical commands
	aliasChecks := []struct {
		path []string
		want string
	}{
		{[]string{"h", "ls"}, "list"},
		{[]string{"h", "ed"}, "edit"},
		{[]string{"h", "rm"}, "delete"},
		{[]string{"h", "pr"}, "probe"},
		{[]string{"h", "imp"}, "import"},
		{[]string{"h", "cred", "set"}, "set"},
		{[]string{"h", "cred", "rm"}, "delete"},
		{[]string{"h", "set-secret"}, "set-secret"},
		{[]string{"h", "rm-secret"}, "delete-secret"},
		{[]string{"id", "ls"}, "list"},
		{[]string{"id", "ed"}, "edit"},
		{[]string{"id", "rm"}, "delete"},
		{[]string{"id", "set"}, "set-secret"},
		{[]string{"id", "unset"}, "delete-secret"},
		{[]string{"id", "cred", "rm"}, "delete"},
		{[]string{"cred", "set"}, "set"},
		{[]string{"cred", "rm"}, "delete"},
		{[]string{"cred", "doc"}, "doctor"},
		{[]string{"cred", "mig"}, "migrate"},
		{[]string{"cred", "fin"}, "finalize-migration"},
		{[]string{"cred", "st", "ls"}, "list"},
		{[]string{"cred", "st", "insp"}, "inspect"},
		{[]string{"cred", "st", "pr"}, "probe"},
	}
	for _, tc := range aliasChecks {
		found, _, err := root.Find(tc.path)
		if err != nil {
			t.Fatalf("find %v failed: %v", tc.path, err)
		}
		if found.Name() != tc.want {
			t.Errorf("find %v = %q, want %q", tc.path, found.Name(), tc.want)
		}
	}
}

func TestMCPCommandRejectsUnknownArguments(t *testing.T) {
	cmd := NewCmdMcp()
	if err := cmd.Args(cmd, []string{"unknown"}); err == nil {
		t.Fatal("mcp Args() error = nil, want unknown argument error")
	}
}
