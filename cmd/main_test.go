package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/i18n"
)

func TestMain(m *testing.M) {
	var cleanupDir string
	// Ensure cmd package tests never read or mutate the developer's real ~/.xops
	// directory even if an individual test omits setupTestEnvironment(t).
	if os.Getenv("XOPS_TEST_ISOLATED") != "1" {
		baseDir, err := os.MkdirTemp("", "xops-cmd-test-env-*")
		if err != nil {
			fmt.Fprintf(os.Stderr, "create isolated test env dir: %v\n", err)
			os.Exit(1)
		}
		if resolved, err := filepath.EvalSymlinks(baseDir); err == nil {
			baseDir = resolved
		}
		cleanupDir = baseDir
		homeDir := filepath.Join(baseDir, "home")
		cfgDir := filepath.Join(baseDir, "config")
		journalDir := filepath.Join(baseDir, "journals")
		for _, dir := range []string{homeDir, cfgDir, journalDir} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				_ = os.RemoveAll(cleanupDir)
				fmt.Fprintf(os.Stderr, "prepare isolated test env dir %s: %v\n", dir, err)
				os.Exit(1)
			}
		}
		for _, kv := range [][2]string{
			{"XOPS_TEST_ISOLATED", "1"},
			{"HOME", homeDir},
			{"USERPROFILE", homeDir},
			{"XOPS_CONFIG_DIR", cfgDir},
			{"XOPS_JOURNAL_DIR", journalDir},
		} {
			if err := os.Setenv(kv[0], kv[1]); err != nil {
				_ = os.RemoveAll(cleanupDir)
				fmt.Fprintf(os.Stderr, "set isolated test env %s: %v\n", kv[0], err)
				os.Exit(1)
			}
		}
	}

	// Helpers re-exec this race-instrumented test binary. Do not charge every
	// helper request the race runtime's default one-second exit sleep. The parent
	// runtime has already initialized; preserve its other options for children.
	if err := os.Setenv("GORACE", strings.TrimSpace(os.Getenv("GORACE")+" atexit_sleep_ms=0")); err != nil {
		if cleanupDir != "" {
			_ = os.RemoveAll(cleanupDir)
		}
		fmt.Fprintf(os.Stderr, "configure test helper race runtime: %v\n", err)
		os.Exit(1)
	}
	if err := i18n.Init("en"); err != nil {
		if cleanupDir != "" {
			_ = os.RemoveAll(cleanupDir)
		}
		fmt.Fprintf(os.Stderr, "failed to initialize i18n for tests: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	if cleanupDir != "" {
		_ = os.RemoveAll(cleanupDir)
	}
	os.Exit(code)
}
