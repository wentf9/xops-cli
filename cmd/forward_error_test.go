package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestForwardRunEReturnsFlagTypeError(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("udp", "", "")

	err := forwardRunE(cmd, []string{"127.0.0.1:1", "127.0.0.1:2"})
	if err == nil {
		t.Fatal("expected udp flag type error")
	}
	if !strings.Contains(err.Error(), "read udp flag") {
		t.Fatalf("unexpected error: %v", err)
	}
}
