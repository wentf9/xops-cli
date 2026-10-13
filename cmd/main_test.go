package cmd

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/i18n"
)

func TestMain(m *testing.M) {
	// Helpers re-exec this race-instrumented test binary. Do not charge every
	// helper request the race runtime's default one-second exit sleep. The parent
	// runtime has already initialized; preserve its other options for children.
	if err := os.Setenv("GORACE", strings.TrimSpace(os.Getenv("GORACE")+" atexit_sleep_ms=0")); err != nil {
		fmt.Fprintf(os.Stderr, "configure test helper race runtime: %v\n", err)
		os.Exit(1)
	}
	if err := i18n.Init("en"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize i18n for tests: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
