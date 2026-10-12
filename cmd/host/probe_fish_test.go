package host

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
)

func TestHostProbeSavesFishDialect(t *testing.T) {
	for _, selector := range []string{"fish-fixture", "--all"} {
		t.Run(selector, func(t *testing.T) {
			repo, store := verificationRepository(t)
			draft, err := prepareImport(repo, utils.HostInfo{Host: "192.0.2.1", User: "root", Alias: "fish-fixture"}, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			if err := draft.save(t.Context(), repo); err != nil {
				t.Fatal(err)
			}
			result := testProbeResult()
			result.DetectedDialect = ssh.LaunchFish
			result.RemoteShellPath = "/usr/bin/fish"
			result.AvailableInterpreters = append(result.AvailableInterpreters, ssh.InterpreterFish)
			result.SuggestedConfig.LaunchDialect = ssh.LaunchFish
			cmd := newCmdInventoryProbe(func(_ context.Context, _ *config.Repository, _ string, check *inventoryVerification) error {
				check.Result = result
				return nil
			})
			var output bytes.Buffer
			cmd.SetArgs([]string{selector, "--save"})
			cmd.SetContext(t.Context())
			cmd.SetOut(&output)
			cmd.SetErr(&output)
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			cfg, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			node, found := cfg.Nodes.Get(draft.nodeID)
			if !found || !reflect.DeepEqual(node.Execution, &result.SuggestedConfig) {
				t.Fatalf("fish recommendation not persisted: %+v", node.Execution)
			}
			if !strings.Contains(output.String(), "bash, sh, fish") || !strings.Contains(output.String(), "/usr/bin/fish") {
				t.Fatalf("missing fish diagnostics: %s", output.String())
			}
		})
	}
}
