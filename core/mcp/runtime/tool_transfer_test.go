package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/mcp/transfer"
	config "github.com/wentf9/xops-cli/core/testutil/mcphost"
	"github.com/wentf9/xops-cli/core/testutil/mcphost/models"
)

func defaultPortTransferRuntime() *Runtime {
	cfg := runtimeTestProvider("implicit").Snapshot()
	cfg.Hosts.Set("host", models.Host{Address: "192.0.2.1"})
	cfg.Hosts.Set("explicit-host", models.Host{Address: "192.0.2.1", Port: 22})
	cfg.Hosts.Set("other-port", models.Host{Address: "192.0.2.1", Port: 2222})
	cfg.Identities.Set("other-user", models.Identity{User: "another"})
	cfg.Nodes.Set("explicit", models.Node{HostRef: "explicit-host", IdentityRef: "identity"})
	cfg.Nodes.Set("different-port", models.Node{HostRef: "other-port", IdentityRef: "identity"})
	cfg.Nodes.Set("different-user", models.Node{HostRef: "host", IdentityRef: "other-user"})
	return &Runtime{provider: config.NewProviderWithoutOpenSSH(cfg)}
}

func TestTransferTargetDefaultsSSHPort(t *testing.T) {
	r := defaultPortTransferRuntime()
	_, implicit, err := r.resolveTransferTarget("implicit")
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range []string{"explicit", "different-port", "different-user"} {
		id, target, err := r.resolveTransferTarget(node)
		if err != nil {
			t.Fatal(err)
		}
		if id != node {
			t.Fatalf("resolved node %q as %q", node, id)
		}
		if (target == implicit) != (node == "explicit") {
			t.Errorf("incorrect destination equivalence for %s", node)
		}
	}
}

func TestDefaultPortAliasCannotBypassTransferFences(t *testing.T) {
	r := defaultPortTransferRuntime()
	journal, err := transfer.OpenJournal(filepath.Join(t.TempDir(), "transfers"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := transfer.NewManager(t.Context(), journal, transfer.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer closeTransferTestResource(t, manager)
	digest := sha256.Sum256(nil)
	specs := make([]transfer.Spec, 0, 2)
	tasks := make([]transfer.Prepared, 0, 2)
	for _, node := range []string{"implicit", "explicit"} {
		id, target, err := r.resolveTransferTarget(node)
		if err != nil {
			t.Fatal(err)
		}
		spec := transfer.Spec{Scope: "test", RequestID: node, NodeID: id, TargetID: target, Direction: transfer.Upload, RemotePath: "/destination", SHA256: hex.EncodeToString(digest[:])}
		task, err := manager.Prepare(spec, node)
		if err != nil {
			t.Fatal(err)
		}
		specs = append(specs, spec)
		tasks = append(tasks, task)
	}
	lease, err := manager.Claim(t.Context(), tasks[0].Status.ID, tasks[0].Token, transfer.Upload)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTransferTestResource(t, lease)
	competing, err := manager.Claim(t.Context(), tasks[1].Status.ID, tasks[1].Token, transfer.Upload)
	if competing != nil {
		closeTransferTestResource(t, competing)
	}
	if !errors.Is(err, transfer.ErrBusy) {
		t.Errorf("default-port alias bypassed path lock: %v", err)
	}
	if _, err := lease.Temporary(); err != nil {
		t.Fatal(err)
	}
	if err := lease.ConfirmTemporary(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Verify(0, specs[0].SHA256); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.BeginCommit(); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.Fail(errors.New("commit reply lost")); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	specs[1].RequestID = "after-unknown"
	if _, err := manager.Prepare(specs[1], "new-operation"); !errors.Is(err, transfer.ErrConflict) {
		t.Errorf("default-port alias bypassed unresolved commit fence: %v", err)
	}
}

func (r *Runtime) resolveTransferTarget(selector string) (string, string, error) {
	parent := r.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 10*time.Second)
	defer cancel()
	view, err := r.resolve(ctx, []string{selector})
	if err != nil {
		return "", "", err
	}
	return transferTarget(view, selector)
}
