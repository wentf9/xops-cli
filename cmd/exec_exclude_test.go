package cmd

import (
	"testing"

	"github.com/wentf9/xops-cli/pkg/i18n"
)

// TestExecExcludeFlagRegistered verifies the --exclude flag is properly registered
// on the exec command and parses comma-separated / repeated values correctly.
func TestExecExcludeFlagRegistered(t *testing.T) {
	if err := i18n.Init("zh"); err != nil {
		t.Fatalf("i18n.Init failed: %v", err)
	}
	c := NewCmdExec()

	flag := c.Flags().Lookup("exclude")
	if flag == nil {
		t.Fatal("expected --exclude flag to be registered on exec command")
	}
	if flag.NoOptDefVal != "" {
		t.Errorf("--exclude should require a value, got NoOptDefVal=%q", flag.NoOptDefVal)
	}

	// Parse args with both comma-separated and repeated --exclude forms
	args := []string{"--exclude", "web-01,web-02", "--exclude", "db-01", "-c", "uptime", "--host", "h1"}
	if err := c.Flags().Parse(args); err != nil {
		t.Fatalf("failed to parse flags: %v", err)
	}

	got, err := c.Flags().GetStringSlice("exclude")
	if err != nil {
		t.Fatalf("failed to get exclude slice: %v", err)
	}

	want := []string{"web-01", "web-02", "db-01"}
	if len(got) != len(want) {
		t.Fatalf("expected %d raw exclude entries, got %d (%v)", len(want), len(got), got)
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("at index %d: expected %q, got %q", i, v, got[i])
		}
	}
}
