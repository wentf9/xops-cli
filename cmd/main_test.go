package cmd

import (
	"fmt"
	"os"
	"testing"

	"github.com/wentf9/xops-cli/pkg/i18n"
)

func TestMain(m *testing.M) {
	if err := i18n.Init("en"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize i18n for tests: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
