package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestP7Repro_MED13_IncludeBudget_CountsGlobFanOutDirsAndDanglingSymlinks verifies MED-13:
// Include glob fan-out over directories, dangling symlinks, and active-cycle symlinks
// charges includeLoadBudget and fails closed instead of probing unboundedly.
func TestP7Repro_MED13_IncludeBudget_CountsGlobFanOutDirsAndDanglingSymlinks(t *testing.T) {
	t.Parallel()

	const fanOutCount = 2100

	t.Run("directory_glob_fanout_counts_against_budget", func(t *testing.T) {
		t.Parallel()
		baseDir := t.TempDir()
		incDir := filepath.Join(baseDir, "dirs")
		if err := os.MkdirAll(incDir, 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		for i := range fanOutCount {
			if err := os.Mkdir(filepath.Join(incDir, fmt.Sprintf("d-%04d", i)), 0o700); err != nil {
				t.Fatalf("Mkdir %d: %v", i, err)
			}
		}
		cfgPath := filepath.Join(baseDir, "ssh_config")
		cfgText := fmt.Sprintf("Include %s/*\nHost app\n    HostName 10.0.0.1\n", incDir)
		if err := os.WriteFile(cfgPath, []byte(cfgText), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		if _, err := NewOpenSSHParserFromPath(cfgPath); err == nil {
			t.Fatalf("MED-13: Include glob over %d directories succeeded without tripping include budget", fanOutCount)
		}
	})

	t.Run("dangling_symlink_glob_fanout_counts_against_budget", func(t *testing.T) {
		t.Parallel()
		baseDir := t.TempDir()
		incDir := filepath.Join(baseDir, "dangling")
		if err := os.MkdirAll(incDir, 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		missingTarget := filepath.Join(baseDir, "does-not-exist")
		for i := range fanOutCount {
			linkPath := filepath.Join(incDir, fmt.Sprintf("l-%04d", i))
			if err := os.Symlink(missingTarget, linkPath); err != nil {
				t.Skipf("os.Symlink unsupported: %v", err)
			}
		}
		cfgPath := filepath.Join(baseDir, "ssh_config")
		cfgText := fmt.Sprintf("Include %s/*\nHost app\n    HostName 10.0.0.1\n", incDir)
		if err := os.WriteFile(cfgPath, []byte(cfgText), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		if _, err := NewOpenSSHParserFromPath(cfgPath); err == nil {
			t.Fatalf("MED-13: Include glob over %d dangling symlinks succeeded without tripping include budget", fanOutCount)
		}
	})

	t.Run("active_cycle_symlink_glob_fanout_counts_against_budget", func(t *testing.T) {
		t.Parallel()
		baseDir := t.TempDir()
		incDir := filepath.Join(baseDir, "cycles")
		if err := os.MkdirAll(incDir, 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		cfgPath := filepath.Join(baseDir, "ssh_config")
		cfgText := fmt.Sprintf("Include %s/*\nHost app\n    HostName 10.0.0.1\n", incDir)
		if err := os.WriteFile(cfgPath, []byte(cfgText), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		for i := range fanOutCount {
			linkPath := filepath.Join(incDir, fmt.Sprintf("c-%04d", i))
			if err := os.Symlink(cfgPath, linkPath); err != nil {
				t.Skipf("os.Symlink unsupported: %v", err)
			}
		}

		if _, err := NewOpenSSHParserFromPath(cfgPath); err == nil {
			t.Fatalf("MED-13: Include glob over %d cycle symlinks succeeded without tripping include budget", fanOutCount)
		}
	})
}

func TestOpenSSHInclude_DevNullUnifiedWithRoot(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	cfgPath := filepath.Join(baseDir, "ssh_config")
	cfgText := fmt.Sprintf("Include %s\nHost ok\n    HostName 10.0.0.2\n", os.DevNull)
	if err := os.WriteFile(cfgPath, []byte(cfgText), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	p, err := NewOpenSSHParserFromPath(cfgPath)
	if err != nil || !p.HasHost("ok") {
		t.Fatalf("Include %q failed: (%v, %v)", os.DevNull, p, err)
	}
	if runtime.GOOS != "windows" {
		nullLink := filepath.Join(baseDir, "null-link")
		if err := os.Symlink(os.DevNull, nullLink); err != nil {
			t.Fatal(err)
		}
		linkCfg := filepath.Join(baseDir, "link_ssh_config")
		if err := os.WriteFile(linkCfg, []byte("Include "+nullLink+"\nHost ok2\n    HostName 10.0.0.3\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		p2, err2 := NewOpenSSHParserFromPath(linkCfg)
		if err2 != nil || !p2.HasHost("ok2") {
			t.Fatalf("Include symlink->%q failed: (%v, %v)", os.DevNull, p2, err2)
		}
	}
}
