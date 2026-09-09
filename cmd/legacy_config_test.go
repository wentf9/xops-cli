package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestLegacyWarningPolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
		args []string
		warn bool
	}{
		{"implicit v1", "identities: {}\n", []string{"host", "list"}, true},
		{"explicit v1 MCP", "schema_version: 1\n", []string{"mcp", "serve"}, true},
		{"v2", "schema_version: 2\n", []string{"host", "list"}, false},
		{"absent", "", []string{"init"}, false},
		{"migration bypasses ordinary policy", "schema_version: 99\n", []string{"credential", "migrate"}, false},
		{"finalize bypasses ordinary policy", "schema_version: 99\n", []string{"credential", "finalize-migration"}, false},
		{"version independent of config", "schema_version: 99\n", []string{"version"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupTestEnvironment(t)
			path := filepath.Join(dir, "xops_config.yaml")
			if tc.data != "" {
				if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			root := newRootCmd()
			initRootFlags(root)
			registerCommands(root)
			leaf, _, err := root.Find(tc.args)
			if err != nil {
				t.Fatal(err)
			}
			leaf.RunE = func(*cobra.Command, []string) error { return nil }
			var out, diagnostic bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&diagnostic)
			root.SetArgs(tc.args)
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(diagnostic.String(), "Schema v1") != tc.warn {
				t.Fatalf("unexpected warning: %q", diagnostic.String())
			}
			if out.Len() != 0 {
				t.Fatalf("warning polluted command stdout: %q", out.String())
			}
			if _, err := os.Stat(filepath.Join(dir, "secret.key")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("schema inspection created key: %v", err)
			}
			if tc.data != "" {
				after, err := os.ReadFile(path)
				if err != nil || string(after) != tc.data {
					t.Fatalf("schema inspection modified config: %v", err)
				}
			}
		})
	}
}

func TestInitReportsV2CredentialPolicy(t *testing.T) {
	setupTestEnvironment(t)
	root := newRootCmd()
	initRootFlags(root)
	registerCommands(root)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(new(bytes.Buffer))
	root.SetArgs([]string{"init", "--skip-ssh-import"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"none", "pass", "helper", "system", "doctor"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("initialization omitted credential guidance %q", want)
		}
	}
	if strings.Contains(out.String(), "secret.key") {
		t.Fatal("initialization reports a legacy key")
	}
}
