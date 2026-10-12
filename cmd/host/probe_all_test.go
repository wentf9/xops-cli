package host

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
)

func TestHostProbeAll(t *testing.T) {
	for _, mode := range []string{"diagnose", "save", "verification failure", "probe failure", "no result", "conflict", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			repo, store := verificationRepository(t)
			// Insert in reverse order to check deterministic selection and output.
			nodeIDs := []string{"root@192.0.2.1:22", "root@192.0.2.2:22", "root@192.0.2.3:22"}
			for _, host := range []string{"192.0.2.3", "192.0.2.2", "192.0.2.1"} {
				draft, err := prepareImport(repo, utils.HostInfo{Host: host, User: "root"}, "fixture")
				if err != nil {
					t.Fatal(err)
				}
				if err := draft.save(t.Context(), repo); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var calls []string
			verifyErr := errors.New("authentication failed")
			cmd := newCmdInventoryProbe(func(ctx context.Context, active *config.Repository, nodeID string, check *inventoryVerification) error {
				calls = append(calls, nodeID)
				if !check.Probe || check.Host.Address == "" {
					t.Error("missing probe flag or connection snapshot")
				}
				check.Result = testProbeResult()
				if nodeID != nodeIDs[0] {
					return nil
				}
				switch mode {
				case "verification failure":
					return verifyErr
				case "probe failure":
					check.ProbeErr = ssh.ErrExecutionProbe
				case "no result":
					check.Result = nil
				case "conflict":
					_, err := active.UpdateNodeTagsContext(ctx, []string{nodeID}, []string{"concurrent"}, true)
					return err
				case "cancel":
					cancel()
					return ctx.Err()
				}
				return nil
			})
			args := []string{"--all"}
			if mode != "diagnose" {
				args = append(args, "--save")
			}
			var output bytes.Buffer
			cmd.SetArgs(args)
			cmd.SetContext(ctx)
			cmd.SetOut(&output)
			cmd.SetErr(new(bytes.Buffer))
			err := cmd.Execute()
			wantErr := mode != "diagnose" && mode != "save"
			if (err != nil) != wantErr {
				t.Fatalf("error = %v, mode = %s", err, mode)
			}
			assertProbeAllErrorCause(t, mode, err, verifyErr)
			wantCalls := nodeIDs
			if mode == "cancel" {
				wantCalls = nodeIDs[:1]
			}
			if !reflect.DeepEqual(calls, wantCalls) {
				t.Fatalf("calls = %v, want %v", calls, wantCalls)
			}
			assertProbeAllSavedNodes(t, store, nodeIDs, mode, output.String())
		})
	}
}

func TestHostProbeAllEmptyInventory(t *testing.T) {
	verificationRepository(t)
	cmd := newCmdInventoryProbe(func(context.Context, *config.Repository, string, *inventoryVerification) error {
		t.Error("empty inventory attempted SSH")
		return nil
	})
	var output bytes.Buffer
	cmd.SetArgs([]string{"--all", "--save"})
	cmd.SetContext(t.Context())
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if output.Len() == 0 {
		t.Fatal("missing empty inventory message")
	}
}

func TestHostProbeTargetArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"--all", "node"}, {"node", "other"}, {"--all=false"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			cmd := newCmdInventoryProbe(func(context.Context, *config.Repository, string, *inventoryVerification) error {
				t.Error("invalid arguments attempted SSH")
				return nil
			})
			cmd.SetArgs(args)
			cmd.SetContext(t.Context())
			cmd.SetOut(new(bytes.Buffer))
			cmd.SetErr(new(bytes.Buffer))
			if err := cmd.Execute(); err == nil {
				t.Fatal("invalid arguments accepted")
			}
		})
	}
}

func assertProbeAllErrorCause(t *testing.T, mode string, err, verifyErr error) {
	t.Helper()
	for _, failure := range []struct {
		mode string
		err  error
	}{
		{"verification failure", verifyErr}, {"probe failure", ssh.ErrExecutionProbe},
		{"conflict", config.ErrConfigConflict}, {"cancel", context.Canceled},
	} {
		if mode == failure.mode && !errors.Is(err, failure.err) {
			t.Fatalf("missing error cause: %v", err)
		}
	}

}

func assertProbeAllSavedNodes(t *testing.T, store config.Store, nodeIDs []string, mode, output string) {
	t.Helper()
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	for index, nodeID := range nodeIDs {
		node, found := cfg.Nodes.Get(nodeID)
		if !found {
			t.Fatalf("missing node %q", nodeID)
		}
		wantSaved := mode != "diagnose" && mode != "cancel" && (index > 0 || mode == "save")
		if (node.Execution != nil) != wantSaved {
			t.Fatalf("%s execution = %+v, want saved %v", nodeID, node.Execution, wantSaved)
		}
		if wantSaved && !reflect.DeepEqual(node.Execution, &testProbeResult().SuggestedConfig) {
			t.Fatalf("incorrect recommendation: %+v", node.Execution)
		}
		if index > 0 && mode != "cancel" && !strings.Contains(output, nodeID) {
			t.Fatalf("missing node output: %s", output)
		}
	}
}

func TestHostProbeAllAggregatesFailures(t *testing.T) {
	repo, _ := verificationRepository(t)
	for _, host := range []string{"192.0.2.1", "192.0.2.2"} {
		draft, err := prepareImport(repo, utils.HostInfo{Host: host, User: "root"}, "fixture")
		if err != nil {
			t.Fatal(err)
		}
		if err := draft.save(t.Context(), repo); err != nil {
			t.Fatal(err)
		}
	}
	authenticationErr := errors.New("authentication failed")
	calls := 0
	cmd := newCmdInventoryProbe(func(_ context.Context, _ *config.Repository, nodeID string, check *inventoryVerification) error {
		calls++
		if nodeID == "root@192.0.2.1:22" {
			return authenticationErr
		}
		check.ProbeErr = ssh.ErrExecutionProbe
		return nil
	})
	cmd.SetArgs([]string{"--all"})
	cmd.SetContext(t.Context())
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	err := cmd.Execute()
	if calls != 2 || !errors.Is(err, authenticationErr) || !errors.Is(err, ssh.ErrExecutionProbe) {
		t.Fatalf("calls = %d, aggregated error = %v", calls, err)
	}
	for _, nodeID := range []string{"root@192.0.2.1:22", "root@192.0.2.2:22"} {
		if !strings.Contains(err.Error(), nodeID) {
			t.Fatalf("missing failed target %q: %v", nodeID, err)
		}
	}
}
