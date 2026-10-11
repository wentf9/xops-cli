package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

// initCredentialPolicyTestI18n mirrors CLI startup so text assertions do not
// depend on another test loading translations first.
func initCredentialPolicyTestI18n(t *testing.T) {
	t.Helper()
	previousLang := i18n.Lang()
	if err := i18n.Init("en"); err != nil {
		t.Fatalf("initialize credential policy test translations: %v", err)
	}
	if previousLang != "" {
		t.Cleanup(func() { i18n.SetLang(previousLang) })
	}
}

func TestLegacyRejectionPolicy(t *testing.T) {
	initCredentialPolicyTestI18n(t)
	for _, tc := range []struct {
		name   string
		data   string
		args   []string
		reject bool
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
			called := false
			leaf.RunE = func(*cobra.Command, []string) error { called = true; return nil }
			var out, diagnostic bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&diagnostic)
			root.SetArgs(tc.args)
			err = root.Execute()
			if errors.Is(err, config.ErrLegacyConfiguration) != tc.reject || (!tc.reject && err != nil) {
				t.Fatalf("unexpected schema policy error: %v", err)
			}
			if called == tc.reject {
				t.Fatalf("command dispatch did not enforce schema policy: called=%t", called)
			}
			if diagnostic.Len() != 0 {
				t.Fatalf("schema policy polluted diagnostics: %q", diagnostic.String())
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
	initCredentialPolicyTestI18n(t)
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
	for _, want := range []string{"encrypted-file", "key-file", "pass", "helper", "system"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("initialization omitted credential guidance %q", want)
		}
	}
	if strings.Contains(out.String(), "secret.key") {
		t.Fatal("initialization reports a legacy key")
	}
}
